# CodeQL: introduction to data-flow 2 for Java

This repository contains 3 example CodeQL queries to demonstrate how to use global data flow in combination with barriers, how to debug global data flow with partial path graphs, and how to extend the data flow graph with additional edges.
The global data flow configuration is using [parameterized modules](https://codeql.github.com/docs/ql-language-reference/modules/#parameterized-modules) instead of extending the data flow `Configuration` class.
The parameterized module way of specifying a global data flow configuration will replace the `Configuration` class.

- [GlobalDataFlow.ql](./queries/GlobalDataFlow.ql) demonstrates two types of barriers in the predicate `isBarrier` and extends the data flow graph with an additional edge in `isAdditionalFlowStep`.
- [CustomBarrierGuard.ql](./queries/CustomBarrierGuard.ql) demonstrates a custom barrier guard to support validation checks on derived values. See `test6` in [Test.java](./tests/CustomBarrierGuard.ql/Test.java) for an example.
- [PartialPathGraph.ql](./queries/PartialPathGraph.ql) demonstrates how the `FlowExploration` module can be used to create a partial path graph to identify missing data flow edges. This can be used to find the missing step when calling the method `concat` in `test8`, found in the file [Test.java](./tests/GlobalDataFlow/Test.java).