/**
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.controlflow.Guards

// Global data-flow configuration as a parameterized module
// Like the DataFlow::Configuration class we have to provide the 
// `isSource` and `isSink` predicates.
// However, we no longer have to override predicates, because we are know working with a module instead of class.
// This configuration module will be used to create our own `DataFlow` or `TaintTracking` module.
// Unike the configuration classes, we can use the same configuration module for both. 
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

// Using our configuration module we can create our own data-flow or taint-tracking module
// that contains all we need to perform globa data flow analysis.
module MyDataFlow = TaintTracking::Global<MyDataFlowConfiguration>;
// We can create multiple data-flow modules based on any configuration.
// That is, we know longer have to import `semmle.code.java.dataflow.DataFlow2`,
// or `semmle.code.java.dataflow.DataFlow3` when we want multiple configurations.
module MyOtherDataFlow = DataFlow::Global<MyDataFlowConfiguration>;

// Here we define our guard check that is used to construct a custom `BarrierGuard`.
// A `BarrierGuard` combines control flow with data-flow to determine if a use of a variable is safe.
// The way that is done is through the `guardChecks` predicate that defines what the `Guard` is,
// what is checks (the `e`) and when it is considered guarded.
// A guard is any expression with boolean type, a switch case, or a method that is detected to be a precondition
// check (e.g., `Preconditions.checkArgument` from `com.google.common.base`), that checks the expression `e` and
// is considered passed for the given value of `branch`. 
// In the test case, the guard is a call to `isValid` and the expression we want to check is passed as an argument.
// When the result is `true` the guard successfully checked the expression `e`.
predicate guardChecks(Guard g, Expr e, boolean branch) {
    exists(MethodAccess ma | ma.getMethod().hasName("isValid") |
        ma = g and
        ma.getAnArgument() = e and
        branch = true
    )
}

// Construct a barrier guard using our `guardChecks` predicate.
// To refer to a predicate (like a function pointer) we have to provide the name of
// the predicate and its arity (the number of parameters it accepts) separated by a `/`.
module ValidatorBarrierGuard = DataFlow::BarrierGuard<guardChecks/3>;

// Import our path graph module from our constructed data-flow module.
import MyDataFlow::PathGraph

// Use our data-flow module to find paths
// Notice that we can directly use our data-flow module in the where clause to use the `hasFlowPath` since this is
// now a member predicate of a module and not a class.
from MyDataFlow::PathNode source, MyDataFlow::PathNode sink
where MyDataFlow::flowPath(source, sink)
select sink, source, sink, "Some alert message"