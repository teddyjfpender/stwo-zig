use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use serde::Serialize;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo_constraint_framework::expr::degree::NamedExprs;
use stwo_constraint_framework::expr::{BaseExpr, ExtExpr};

const UPSTREAM_COMMIT: &str = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";
const SCHEMA_VERSION: u32 = 1;
const SEED_STRATEGY: &str = "fixed deterministic assignments and named-expression degree fixtures";

#[derive(Debug, Clone, Serialize)]
struct Meta {
    upstream_commit: &'static str,
    schema_version: u32,
    sample_count: usize,
    seed_strategy: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ColumnValue {
    interaction: usize,
    idx: usize,
    offset: isize,
    value: u32,
}

#[derive(Debug, Clone, Serialize)]
struct BaseParamValue {
    name: String,
    value: u32,
}

#[derive(Debug, Clone, Serialize)]
struct ExtParamValue {
    name: String,
    value: [u32; 4],
}

#[derive(Debug, Clone, Serialize)]
struct CaseVector {
    name: String,
    columns: Vec<ColumnValue>,
    params: Vec<BaseParamValue>,
    ext_params: Vec<ExtParamValue>,
    base_eval: Option<u32>,
    ext_eval: Option<[u32; 4]>,
    base_degree: Option<usize>,
    ext_degree: Option<usize>,
    base_format: Option<String>,
    ext_format: Option<String>,
    base_simplified_format: Option<String>,
    ext_simplified_format: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Root {
    meta: Meta,
    cases: Vec<CaseVector>,
}

fn main() {
    let out_path = parse_out_path();

    let cases = vec![base_arith_case(), ext_arith_case(), degree_named_case()];

    let root = Root {
        meta: Meta {
            upstream_commit: UPSTREAM_COMMIT,
            schema_version: SCHEMA_VERSION,
            sample_count: cases.len(),
            seed_strategy: SEED_STRATEGY,
        },
        cases,
    };

    let json = serde_json::to_string_pretty(&root).expect("serialize constraint vectors");
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create parent directories");
    }
    fs::write(&out_path, json).expect("write vectors");
}

fn parse_out_path() -> PathBuf {
    let mut args = env::args().skip(1);
    let mut out = PathBuf::from("vectors/constraint_expr.json");

    while let Some(arg) = args.next() {
        if arg == "--out" {
            let value = args.next().expect("missing value for --out");
            out = PathBuf::from(value);
            continue;
        }
        panic!("unknown argument: {arg}");
    }

    out
}

fn base_arith_case() -> CaseVector {
    let columns = vec![
        ColumnValue {
            interaction: 1,
            idx: 0,
            offset: 0,
            value: 12,
        },
        ColumnValue {
            interaction: 1,
            idx: 1,
            offset: -1,
            value: 5,
        },
    ];
    let params = vec![
        BaseParamValue {
            name: "a".to_string(),
            value: 3,
        },
        BaseParamValue {
            name: "b".to_string(),
            value: 4,
        },
        BaseParamValue {
            name: "c".to_string(),
            value: 7,
        },
    ];

    let expr = (BaseExpr::Col((1, 0, 0).into()) + BaseExpr::Param("a".to_string()))
        * (BaseExpr::Col((1, 1, -1).into()) - BaseExpr::Param("b".to_string()))
        + BaseExpr::Param("c".to_string()).inverse();

    let assignment = make_assignment(&columns, &params, &[]);
    let base_eval = expr.assign(&assignment).0;

    let named = NamedExprs::new(HashMap::new(), HashMap::new());

    CaseVector {
        name: "base_arith".to_string(),
        columns,
        params,
        ext_params: vec![],
        base_eval: Some(base_eval),
        ext_eval: None,
        base_degree: Some(expr.degree_bound(&named)),
        ext_degree: None,
        base_format: Some(expr.format_expr()),
        ext_format: None,
        base_simplified_format: Some(expr.simplify_and_format()),
        ext_simplified_format: None,
    }
}

fn ext_arith_case() -> CaseVector {
    let columns = vec![
        ColumnValue {
            interaction: 1,
            idx: 0,
            offset: 0,
            value: 12,
        },
        ColumnValue {
            interaction: 1,
            idx: 1,
            offset: 0,
            value: 5,
        },
    ];
    let params = vec![
        BaseParamValue {
            name: "a".to_string(),
            value: 3,
        },
        BaseParamValue {
            name: "b".to_string(),
            value: 4,
        },
    ];
    let ext_params = vec![ExtParamValue {
        name: "q".to_string(),
        value: [1, 2, 3, 4],
    }];

    let expr = ExtExpr::SecureCol([
        Box::new(BaseExpr::Col((1, 0, 0).into()) - BaseExpr::Col((1, 1, 0).into())),
        Box::new(BaseExpr::Col((1, 1, 0).into()) * (-BaseExpr::Param("a".to_string()))),
        Box::new(BaseExpr::Param("a".to_string()) + BaseExpr::Param("a".to_string()).inverse()),
        Box::new(BaseExpr::Param("b".to_string()) * BaseField::from(7)),
    ]) + ExtExpr::Param("q".to_string()) * ExtExpr::Param("q".to_string())
        - SecureField::from_m31_array([
            BaseField::from(1),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
        ]);

    let assignment = make_assignment(&columns, &params, &ext_params);
    let ext_eval = secure_to_u32(expr.assign(&assignment));

    let named = NamedExprs::new(HashMap::new(), HashMap::new());

    CaseVector {
        name: "ext_arith".to_string(),
        columns,
        params,
        ext_params,
        base_eval: None,
        ext_eval: Some(ext_eval),
        base_degree: None,
        ext_degree: Some(expr.degree_bound(&named)),
        base_format: None,
        ext_format: Some(expr.format_expr()),
        base_simplified_format: None,
        ext_simplified_format: Some(expr.simplify_and_format()),
    }
}

fn degree_named_case() -> CaseVector {
    let intermediate = (BaseExpr::Col((1, 1, 0).into()) + BaseField::from(12))
        * BaseExpr::Param("a".to_string())
        * BaseExpr::Col((1, 0, 0).into());

    let qintermediate = ExtExpr::SecureCol([
        Box::new(intermediate.clone()),
        Box::new(BaseField::from(12).into()),
        Box::new(BaseExpr::Param("b".to_string())),
        Box::new(BaseField::from(0).into()),
    ]);

    let low_degree_intermediate = BaseExpr::from(BaseField::from(12_345));

    let named = NamedExprs::new(
        [
            ("intermediate".to_string(), intermediate.clone()),
            (
                "low_degree_intermediate".to_string(),
                low_degree_intermediate.clone(),
            ),
        ]
        .into(),
        [("qintermediate".to_string(), qintermediate.clone())].into(),
    );

    let expr = BaseExpr::Param("intermediate".to_string()) * BaseExpr::Col((2, 1, 0).into());
    let qexpr = BaseExpr::Param("qintermediate".to_string())
        * ExtExpr::SecureCol([
            Box::new(BaseExpr::Col((2, 1, 0).into())),
            Box::new(expr.clone()),
            Box::new(BaseField::from(0).into()),
            Box::new(BaseField::from(1).into()),
        ]);

    CaseVector {
        name: "degree_named".to_string(),
        columns: vec![],
        params: vec![],
        ext_params: vec![],
        base_eval: None,
        ext_eval: None,
        base_degree: Some(expr.degree_bound(&named)),
        ext_degree: Some(qexpr.degree_bound(&named)),
        base_format: Some(expr.format_expr()),
        ext_format: Some(qexpr.format_expr()),
        base_simplified_format: Some(expr.simplify_and_format()),
        ext_simplified_format: Some(qexpr.simplify_and_format()),
    }
}

fn make_assignment(
    columns: &[ColumnValue],
    params: &[BaseParamValue],
    ext_params: &[ExtParamValue],
) -> (
    HashMap<(usize, usize, isize), BaseField>,
    HashMap<String, BaseField>,
    HashMap<String, SecureField>,
) {
    let mut column_values = HashMap::new();
    for col in columns {
        column_values.insert(
            (col.interaction, col.idx, col.offset),
            BaseField::from(col.value),
        );
    }

    let mut param_values = HashMap::new();
    for param in params {
        param_values.insert(param.name.clone(), BaseField::from(param.value));
    }

    let mut ext_values = HashMap::new();
    for param in ext_params {
        ext_values.insert(param.name.clone(), secure_from_u32(param.value));
    }

    (column_values, param_values, ext_values)
}

fn secure_from_u32(value: [u32; 4]) -> SecureField {
    SecureField::from_m31_array([
        BaseField::from(value[0]),
        BaseField::from(value[1]),
        BaseField::from(value[2]),
        BaseField::from(value[3]),
    ])
}

fn secure_to_u32(value: SecureField) -> [u32; 4] {
    let arr = value.to_m31_array();
    [arr[0].0, arr[1].0, arr[2].0, arr[3].0]
}
