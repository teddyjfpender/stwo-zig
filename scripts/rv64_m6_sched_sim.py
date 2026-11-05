import json,sys,heapq
def load(p):
    d=json.load(open(p)); ns=d["nodes"]
    out=[]
    for n in ns:
        s=n["stamps"]
        out.append(dict(id=n["id"],leaf=n["kind"]=="leaf",first=n["first_leaf"],cnt=n["leaf_count"],
            prep=(s["prep_end"]-s["prep_start"])/1e9,dev=(s["device_end"]-s["device_start"])/1e9,fin=(s["finish_end"]-s["finish_start"])/1e9))
    return out,d["dag_wall_ns"]/1e9
def plan(n):  # binary carry ids (matches ready_dag for arity 2)
    nodes=[];stack=[None]*10;kids={}
    def app(nd): nodes.append(nd); return len(nodes)-1
    for o in range(n):
        cur=app(("leaf",o)); lvl=0
        while stack[lvl] is not None:
            p=app(("fold",)); kids[p]=(stack[lvl],cur); stack[lvl]=None; cur=p; lvl+=1
        stack[lvl]=cur
    carry=None
    for lvl in range(10):
        if stack[lvl] is not None:
            if carry is None: carry=stack[lvl]
            else: p=app(("fold",)); kids[p]=(stack[lvl],carry); carry=p
    return len(nodes),kids,carry
def sim(nodes,policy="cur",static=False,lanes=2,host=8,ahead=6,conc=1,slow=1.0,leaf_ready=None,dev_ready=0.0):
    N=len(nodes); n_leaf=sum(x["leaf"] for x in nodes)
    cnt,kids,root=plan(n_leaf); assert cnt==N
    parent={}
    for p,(l,r) in kids.items(): parent[l]=p; parent[r]=p
    # bottom level: remaining critical path to root (dev+prep+fin of ancestors)
    def up(i):
        t=0
        while i in parent: i=parent[i]; t+=nodes[i]["prep"]+nodes[i]["dev"]+nodes[i]["fin"]
        return t
    blev={i:up(i)+nodes[i]["dev"] for i in range(N)}
    if static:
        def depth(i):
            d=0
            while i in parent: i=parent[i]; d+=1
            return d
        blev={i:depth(i)*1.0+(0.5 if nodes[i]["leaf"] else 0.0)+(nodes[i]["cnt"]*1e-3) for i in range(N)}
    status=["pend"]*N; t=0.0; ev=[]; seq=0
    free_host=host; free_dev=[conc]*lanes; ready=[]; fin_q=[]; leaves_ahead=0
    def push(tm,kind,i,lane=None):
        nonlocal seq; seq+=1; heapq.heappush(ev,(tm,seq,kind,i,lane))
    done=0; last_leaf=0
    if leaf_ready:
        for x in leaf_ready: push(x,'tick',-1)
    push(dev_ready,'tick',-1)
    while True:
        progressed=True
        while progressed:
            progressed=False
            # host: finishing first
            while free_host>0 and fin_q:
                i=fin_q.pop(0); free_host-=1; push(t+nodes[i]["fin"],"fin",i); progressed=True
            while free_host>0:
                cand=None
                for i in range(N):
                    if status[i]!="pend": continue
                    if not nodes[i]["leaf"]:
                        if all(status[k]=="done" for k in kids[i]): cand=i;break
                if cand is None and leaves_ahead<ahead:
                    lv=[i for i in range(N) if status[i]=="pend" and nodes[i]["leaf"] and (leaf_ready is None or leaf_ready[nodes[i]["first"]]<=t)]
                    if lv:
                        if policy in("cp","cpleaf"): lv.sort(key=lambda i:(-blev[i],i))
                        cand=lv[0]
                if cand is None: break
                status[cand]="prep"; free_host-=1
                if nodes[cand]["leaf"]: leaves_ahead+=1
                push(t+nodes[cand]["prep"],"prep",cand); progressed=True
            for lane in range(lanes):
                while free_dev[lane]>0 and ready and t>=dev_ready:
                    if policy=="cur": ready.sort(key=lambda i:(-nodes[i]["cnt"],i))
                    else: ready.sort(key=lambda i:(-blev[i],i))
                    i=ready.pop(0); free_dev[lane]-=1
                    if nodes[i]["leaf"]: leaves_ahead-=1
                    busy=conc-free_dev[lane]
                    push(t+nodes[i]["dev"]*(slow if busy>1 or conc>1 else 1),"dev",i,lane); progressed=True
        if not ev: break
        t,_,kind,i,lane=heapq.heappop(ev)
        if kind=="prep": free_host+=1; status[i]="ready"; ready.append(i)
        elif kind=="dev": free_dev[lane]+=1; fin_q.append(i)
        elif kind=="tick": pass
        elif kind=="fin":
            free_host+=1; status[i]="done"; done+=1
            if nodes[i]["leaf"]: last_leaf=t
    return t,last_leaf
if __name__=="__main__":
    for p in sys.argv[1:]:
        nodes,wall=load(p)
        print(p,"measured",round(wall,2), "sim cur",[round(x,2) for x in sim(nodes,"cur")],"cp",[round(x,2) for x in sim(nodes,"cp")])
        for conc,slow in ((2,1.3),(2,1.5),(2,1.7),(3,2.2)):
            print("  conc",conc,"slow",slow,"cur",[round(x,2) for x in sim(nodes,"cur",conc=conc,slow=slow)],"cp",[round(x,2) for x in sim(nodes,"cp",conc=conc,slow=slow)])
        print("  host16 ahead12 cp",[round(x,2) for x in sim(nodes,"cp",host=16,ahead=12)])
        print("  prep-free head (leaves prepped during native) cp",[round(x,2) for x in sim([dict(x,prep=0 if x["leaf"] else x["prep"]) for x in nodes],"cp")])
        print("  fold prep halved cp",[round(x,2) for x in sim([dict(x,prep=x["prep"]/2 if not x["leaf"] else x["prep"]) for x in nodes],"cp")])
