package chanllenge.spring_security.authorization.util;

public class RequestMatcherEntry<T> {

    private final RequestMatcher requestMatcher;
    private final T entry;

    public RequestMatcherEntry(RequestMatcher requestMatcher, T entry) {
        this.requestMatcher = requestMatcher;
        this.entry = entry;
    }

    public RequestMatcher getRequestMatcher() {
        return requestMatcher;
    }

    public T getEntry() {
        return entry;
    }

}
