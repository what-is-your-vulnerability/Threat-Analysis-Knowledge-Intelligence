package app;
public enum Sort {
    NEWEST("n");
    private final String value;
    Sort(String value) { this.value = value; }
    public static Sort parse(String v) { return NEWEST; }
    public String value() { return value; }
}
