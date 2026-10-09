import S31.Semantics.Json

/-- Executable regression adapter, not a proof oracle. `eval` outputs never
enter a theorem or the axiom audit. One request per JSON line. -/
def main : IO UInt32 := do
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  repeat
    let line ← stdin.getLine
    if line.isEmpty then break
    let result := do
      let request ← Lean.Json.parse line
      S31.Json.objectFields request ["program", "assignment"]
      S31.Json.evaluate (← request.getObjVal? "program") (← request.getObjVal? "assignment")
    let response := match result with
      | .ok words => Lean.Json.mkObj [("ok", Lean.toJson words)]
      | .error message => Lean.Json.mkObj [("error", Lean.Json.str message)]
    stdout.putStrLn response.compress
  return 0
