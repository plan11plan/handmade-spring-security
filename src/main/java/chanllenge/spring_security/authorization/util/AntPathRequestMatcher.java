package chanllenge.spring_security.authorization.util;

public class AntPathRequestMatcher implements RequestMatcher {


    private final String pattern;

    public AntPathRequestMatcher(String pattern) {
        if (pattern == null || pattern.trim().isEmpty()) {
            throw new IllegalArgumentException();
        }
        this.pattern = pattern;
    }

    @Override
    public boolean matches(String url) {
        if (url == null) {
            return false;
        }

        String regex = convertAntPatternToRegex(pattern);
        return url.matches(regex);
    }

    private String convertAntPatternToRegex(String antPattern) {
        StringBuilder regex = new StringBuilder("^");

        int i = 0;
        while (i < antPattern.length()) {
            char c = antPattern.charAt(i);

            if (c == '*') {
                if (i + 1 < antPattern.length() && antPattern.charAt(i + 1) == '*') {
                    regex.append(".*");
                    i += 2;
                } else {
                    regex.append("[^/]*");
                    i++;
                }
            } else if (c == '?') {
                regex.append(".");
                i++;
            } else if (c == '.' || c == '+' || c == '(' || c == ')' ||
                       c == '[' || c == ']' || c == '{' || c == '}' ||
                       c == '^' || c == '$' || c == '|' || c == '\\') {
                regex.append("\\").append(c);
                i++;
            } else {
                regex.append(c);
                i++;
            }
        }

        regex.append("$");
        return regex.toString();
    }

    public String getPattern() {
        return pattern;
    }

    @Override
    public String toString() {
        return "AntPathRequestMatcher{pattern='" + pattern + "'}";
    }
}
