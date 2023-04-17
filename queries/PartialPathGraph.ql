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
         or
         DerivedValidaorBarrierGuard::getABarrierNode() = node
     }
 
    // Disable the addition step to demonstrate finding this missing step.
    //  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    //      exists(MethodAccess ma | ma.getMethod().hasName("concat") | 
    //          ma.getAnArgument() = node1.asExpr() and
    //          ma = node2.asExpr()
 
    //      )
    //  }
 }
 
 module MyDataFlow = TaintTracking::Make<MyDataFlowConfiguration>;
 module MyOtherDataFlow = DataFlow::Make<MyDataFlowConfiguration>;
 
 signature predicate customGuardChecksSig(Guard g, Expr e, boolean branch);
 module CustomBarrierGuard<customGuardChecksSig/3 customGuardChecks> {
     /** Gets a node that is safely guarded by the given guard check. */
     DataFlow::Node getABarrierNode() {
       exists(Guard g, SsaVariable v, boolean branch, SsaVariable derivedV, RValue use |
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
 
 module ValidatorBarrierGuard = DataFlow::BarrierGuard<guardChecks/3>;
 module DerivedValidaorBarrierGuard = CustomBarrierGuard<guardChecks/3>;
 
 // The exploration limit is an approximation of the interprocedural steps taken during flow exploration.
 // This will limit the number of interprocedural steps to make the flow exploration computable.
 // You typically start with 3 steps and adjust as necessary.
 // Adjusting is necessary if all the partial flows indicate no missing edges and you have no partial paths reacing a sink. 
 int explorationLimit() {
     result = 3
 }
 
 // Instantiate the FlowExploration module with out explorationLimit predicate.
 module MyFlowExploration = MyDataFlow::FlowExploration<explorationLimit/0>;
 
// Import the partial path graph to render partial path graphs in the result view.
 import MyFlowExploration::PartialPathGraph
 
 from MyFlowExploration::PartialPathNode source, MyFlowExploration::PartialPathNode node
 where MyFlowExploration::hasPartialFlow(source, node, _) 
 select source.getNode(), source, node, "Partial flow"