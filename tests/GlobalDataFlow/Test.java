class Source {

    public static String getData() {
        return "Data";
    }

}

class Sink {

    public static void sink(String data) {

    }
}

class Sanitizer {
    public static String removeDangerousChars(String data) {
        return data;
    }
}

class Validator {
    public static boolean isValid(String data) {
        return data.length() > 1;
    }
}

class SomeDependency {

    public static String concat(String s1, String s2) {
        // Definition opaque to QL, simulated by breaking data flow
        return "";
    }
}

class Test {
    void test1() {
        String data = Source.getData();

        Sink.sink(data); // TP
    }

    void test2() {
        String data = Source.getData();

        String safeData = Sanitizer.removeDangerousChars(data);
        Sink.sink(safeData);
    }

    void test3() {
        String data = Source.getData();

        if (Validator.isValid(data)) {
            Sink.sink(data);
        }
    }

    void test4() {
        String data = Source.getData();

        if (!Validator.isValid(data)) {
            return;
        }
        Sink.sink(data);
        
    }

    void test5() {
        String data = Source.getData();
        // Incorrect validation
        if (!Validator.isValid(data)) {
            Sink.sink(data); // TP
        }
    }

      void test6() {
        String data = Source.getData();

        String partOfData = data.substring(0, 5);

        if (Validator.isValid(partOfData)) {
            Sink.sink(data); // TP (no custom guard written yet)
        }
    }

    void test7() {
        String data = Source.getData();

        String partOfData = data.substring(0, 5);
        // Incorrect validation
        if (!Validator.isValid(partOfData)) {
            Sink.sink(data); // TP
        }
    }

    void test8() {
        String data = Source.getData();

        String stillUnsafe = SomeDependency.concat("somePrefix", data);

        Sink.sink(stillUnsafe); // TP
        
    }
}