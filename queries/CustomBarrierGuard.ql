/**
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.controlflow.Guards
import semmle.code.java.dataflow.SSA

module MyDataFlowConfiguration implements DataFlow::ConfigSig{
    predicate isSource(DataFlow::Node node) {
        exists(MethodAccess ma | ma.getMethod().hasName("getData") | 
            node.asExpr() = ma
        )
    }

    predicate isSink(DataFlow::Node node) {
        exists(MethodAccess ma | ma.getMethod().hasName("sink") |
            ma.getAnArgument() = node.asExpr()
        )
    }

    predicate isBarrier(DataFlow::Node node) {
        exists(MethodAccess ma | ma.getMethod().hasName("removeDangerousChars") |
            ma.getAnArgument() = node.asExpr()
        )
        or
        ValidatorBarrierGuard::getABarrierNode() = node
    }

    predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
        exists(MethodAccess ma | ma.getMethod().hasName("concat") | 
            ma.getAnArgument() = node1.asExpr() and
            ma = node2.asExpr()

        )
    }
}

module MyDataFlow = TaintTracking::Make<MyDataFlowConfiguration>;

// Copied signature and barrier guard from semmle/code/java/dataflow/internal/DataFlowUtil.qll
signature predicate guardChecksSig(Guard g, Expr e, boolean branch);
// This is the BarrierGuard implementation from the standard library with a modification to reason about
// checks on derived values.
// An example of a derived value is: `String protocol = url.substring(0, 5)`
// The check will validate the derived value to determine if the source value is safe to use.
module BarrierGuard<guardChecksSig/3 customGuardChecks> {
    /** Gets a node that is safely guarded by the given guard check. */
    DataFlow::Node getABarrierNode() {
      exists(Guard g, SsaVariable v, boolean branch, SsaVariable derivedV, RValue use |
        // Add an additional possiblity where a derived value is use to guard a use of our value.
        // Using taint tracking we determine if a derived value, or the value itself (`localExprTaint` is reflexive)
        // is checked by our guard.
        TaintTracking::localExprTaint(v.getAUse(), derivedV.getAUse()) and
        customGuardChecks(g, derivedV.getAUse(), branch) and
        use = v.getAUse() and
        g.controls(use.getBasicBlock(), branch) and
        result.asExpr() = use
      )
    }
  }

predicate guardChecks(Guard g, Expr e, boolean branch) {
    exists(MethodAccess ma | ma.getMethod().hasName("isValid") |
        ma = g and
        ma.getAnArgument() = e and
        branch = true
    )
}

module ValidatorBarrierGuard = BarrierGuard<guardChecks/3>;

import MyDataFlow::PathGraph

from MyDataFlow::PathNode source, MyDataFlow::PathNode sink
where MyDataFlow::hasFlowPath(source, sink)
select sink, source, sink, "Some alert message"