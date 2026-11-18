import sqlite3
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rv64.rv64_m7_gpu_seconds_lib.census import request_census
from scripts.rv64.rv64_m7_gpu_seconds_lib.ranges import native_ranges


class ActivityTests(unittest.TestCase):
    def database(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.executescript('''
            CREATE TABLE StringIds(id INTEGER, value TEXT);
            CREATE TABLE CUPTI_ACTIVITY_KIND_RUNTIME(start INTEGER,end INTEGER,correlationId INTEGER,nameId INTEGER);
            CREATE TABLE CUPTI_ACTIVITY_KIND_MEMCPY(start INTEGER,end INTEGER,correlationId INTEGER,bytes INTEGER,copyKind INTEGER);
            INSERT INTO StringIds VALUES (1,'cudaMemcpyPeerAsync_v4000'),(2,'cudaMemcpyAsync_v3020'),(3,'cudaEventSynchronize_v3020');
            INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES (110,120,1,1),(130,140,2,2),(90,95,3,2),(160,220,4,3);
            INSERT INTO CUPTI_ACTIVITY_KIND_MEMCPY VALUES (125,135,1,32,2),(145,155,2,64,2),(96,105,3,16,2),(145,155,2,1000,1);
        ''')
        return db

    def test_peer_transport_is_separate_from_ordinary_and_unattributed_readbacks(self):
        result = request_census(self.database(), 100, 200)
        self.assertEqual(result['status'], 'MEASURED')
        d2h = result['d2h_activities']
        self.assertEqual(d2h['peer_transport'], {'activities': 1, 'bytes': 32})
        self.assertEqual(d2h['ordinary_cuda_copy'], {'activities': 1, 'bytes': 64})
        self.assertEqual(d2h['unattributed'], {'activities': 1, 'bytes': 16})
        self.assertEqual(result['host_synchronization_calls'], 1)
        self.assertEqual(result['runtime_api_duration_sum_ns']['cudaEventSynchronize_v3020'], 40)

    def test_ambiguous_correlations_are_not_guessed(self):
        db = self.database()
        db.execute('INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES (115,120,1,2)')
        result = request_census(db, 100, 200)
        self.assertEqual(result['d2h_activities']['peer_transport']['activities'], 0)
        self.assertEqual(result['d2h_activities']['unattributed']['activities'], 2)

    def test_missing_tables_are_unavailable_instead_of_zero(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        result = request_census(db, 100, 200)
        self.assertEqual(result['status'], 'UNAVAILABLE')
        self.assertIsNone(result['runtime_api_entered'])
        self.assertIsNone(result['d2h_activities'])

    def test_invalid_windows_fail(self):
        for bounds in ((200, 100), (100, 100), (True, 200)):
            with self.assertRaises(ValueError):
                request_census(self.database(), *bounds)

    def traced_database(self):
        db = self.database()
        db.executescript('''
            CREATE TABLE NVTX_EVENTS(start INTEGER,end INTEGER,globalTid INTEGER,text TEXT,textId INTEGER);
            ALTER TABLE CUPTI_ACTIVITY_KIND_RUNTIME ADD COLUMN globalTid INTEGER;
            UPDATE CUPTI_ACTIVITY_KIND_RUNTIME SET globalTid=10;
            INSERT INTO StringIds VALUES (4,'rv64/gpu/fold/7');
            INSERT INTO NVTX_EVENTS VALUES (105,150,10,NULL,4);
            INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES (115,118,5,2,11);
        ''')
        return db

    def test_native_ranges_count_only_contained_calls_on_owner_thread(self):
        result = native_ranges(self.traced_database(), 100, 200)
        self.assertEqual(result['status'], 'MEASURED')
        self.assertEqual(result['ranges'], [{
            'label': 'rv64/gpu/fold/7', 'thread': 10, 'host_enqueue_ns': 45,
            'runtime_api_contained': {'cudaMemcpyAsync_v3020': 1, 'cudaMemcpyPeerAsync_v4000': 1}}])
        self.assertIn('not device durations', result['scope'])

    def test_incomplete_ranges_are_explicitly_partial(self):
        db = self.traced_database()
        db.executescript('''
            INSERT INTO NVTX_EVENTS VALUES (99,120,10,'rv64/gpu/root/0',NULL);
            INSERT INTO NVTX_EVENTS VALUES (180,NULL,10,'rv64/gpu/leaf/3',NULL);
            INSERT INTO NVTX_EVENTS VALUES (180,190,10,'rv64/gpu/malformed',NULL);
        ''')
        result = native_ranges(db, 100, 200)
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(len(result['ranges']), 1)
        self.assertEqual(len(result['excluded_incomplete_or_malformed_ranges']), 3)

    def test_device_work_uses_submitting_process_and_thread_and_clips_kernels(self):
        db = self.traced_database()
        db.executescript("""
            CREATE TABLE CUPTI_ACTIVITY_KIND_KERNEL(start,end,deviceId,globalPid,correlationId);
            INSERT INTO CUPTI_ACTIVITY_KIND_KERNEL VALUES
                (190,220,0,0,1),(155,180,1,0,1),(155,180,0,16777216,1),
                (95,110,0,0,3),(125,130,0,0,5),(101,109,0,0,99);
            INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES (110,115,1,1,16777226);
            INSERT INTO NVTX_EVENTS VALUES (105,150,16777226,'rv64/gpu/root/2',NULL);
        """)
        stages = request_census(db, 100, 200)['device_kernel_work']['devices']
        self.assertEqual(stages['0'], {
            'fold': {'kernels': 1, 'duration_sum_ns': 10},
            'root': {'kernels': 1, 'duration_sum_ns': 25},
            'unattributed': {'kernels': 3, 'duration_sum_ns': 23},
        })
        self.assertEqual(stages['1']['fold'], {'kernels': 1, 'duration_sum_ns': 25})

    def test_nested_ranges_and_duplicate_runtime_ids_leave_work_unattributed(self):
        db = self.traced_database()
        db.executescript("""
            CREATE TABLE CUPTI_ACTIVITY_KIND_KERNEL(start,end,deviceId,globalPid,correlationId);
            INSERT INTO CUPTI_ACTIVITY_KIND_KERNEL VALUES (143,150,0,0,1),(160,193,0,0,2);
            INSERT INTO NVTX_EVENTS VALUES (108,125,10,'rv64/gpu/leaf/1',NULL);
            INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES (104,108,2,1,10);
        """)
        work = request_census(db, 100, 200)['device_kernel_work']
        self.assertEqual(work['devices'], {'0': {
            'unattributed': {'kernels': 2, 'duration_sum_ns': 40}}})
        self.assertEqual(work['status'], 'PARTIAL')

    def test_unknown_correlation_and_a_range_boundary_do_not_assign_a_kernel(self):
        db = self.traced_database()
        db.executescript("""
            CREATE TABLE CUPTI_ACTIVITY_KIND_KERNEL(start,end,deviceId,globalPid,correlationId);
            INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES (130,140,0,1,10);
            INSERT INTO NVTX_EVENTS VALUES (138,148,10,'rv64/gpu/leaf/2',NULL);
            INSERT INTO CUPTI_ACTIVITY_KIND_KERNEL VALUES (151,151,0,0,0),(155,170,0,0,2);
        """)
        stages = request_census(db, 100, 200)['device_kernel_work']['devices']
        self.assertEqual(stages['0'], {'unattributed': {'kernels': 2, 'duration_sum_ns': 15}})

    def test_device_projection_requires_kernel_origin_columns_and_instrumentation(self):
        db = self.traced_database()
        self.assertEqual(request_census(db, 100, 200)['device_kernel_work']['status'], 'UNAVAILABLE')
        db.execute('CREATE TABLE CUPTI_ACTIVITY_KIND_KERNEL(start,end,deviceId,globalPid,correlationId)')
        db.execute('DELETE FROM NVTX_EVENTS')
        self.assertEqual(request_census(db, 100, 200)['device_kernel_work']['status'], 'NOT_INSTRUMENTED')

    def test_range_coverage_is_not_zero_when_absent(self):
        db = self.database()
        self.assertEqual(native_ranges(db, 100, 200)['status'], 'UNAVAILABLE')
        db.executescript('CREATE TABLE NVTX_EVENTS(start INTEGER,end INTEGER,globalTid INTEGER,text TEXT,textId INTEGER);')
        result = native_ranges(db, 100, 200)
        self.assertEqual(result['status'], 'NOT_INSTRUMENTED')
        self.assertIsNone(result['ranges'])


if __name__ == '__main__':
    unittest.main()
