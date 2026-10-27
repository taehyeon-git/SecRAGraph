/**
 * @name FastAPI cross-file flow fixture
 * @description Demonstrates a request parameter crossing files to an inert modeled sink.
 * @kind path-problem
 * @problem.severity warning
 * @id py/secragraph-fastapi-cross-file-flow-fixture
 * @tags security
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

module FixtureFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource and
    source.getLocation().getFile().getRelativePath().matches("%codeql_flow/app.py")
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asExpr().(Name).getId() = "observe" and
      call.getLocation().getFile().getRelativePath().matches("%codeql_flow/flow.py") and
      sink = call.getArg(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asExpr().(Name).getId() = "allowlisted" and
      call.getLocation().getFile().getRelativePath().matches("%codeql_flow/app.py") and
      node = call
    )
  }
}

module FixtureFlow = TaintTracking::Global<FixtureFlowConfig>;
import FixtureFlow::PathGraph

from FixtureFlow::PathNode source, FixtureFlow::PathNode sink
where FixtureFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Request data reaches the fixture's inert sink."
