package chanllenge.spring_security.authorization.architecture.request;

import chanllenge.spring_security.authentication.context.GrantedAuthority;
import chanllenge.spring_security.authentication.context.SimpleGrantedAuthority;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.util.Assert;

public final class RoleHierarchyImpl implements RoleHierarchy {

    private static final String ROLE_HIERARCHY_NULL = "roleHierarchyRepresentation은 null일 수 없습니다";

    private Map<String, Set<String>> rolesReachableInOneOrMoreSteps = new HashMap<>();

    public void setHierarchy(String roleHierarchyRepresentation) {
        Assert.notNull(roleHierarchyRepresentation, ROLE_HIERARCHY_NULL);
        this.rolesReachableInOneOrMoreSteps = buildRolesReachableInOneOrMoreSteps(roleHierarchyRepresentation);
    }

    @Override
    public Collection<? extends GrantedAuthority> getReachableGrantedAuthorities(
            Collection<? extends GrantedAuthority> authorities) {

        if (authorities == null || authorities.isEmpty()) {
            return new ArrayList<>();
        }

        Set<GrantedAuthority> reachableRoles = new HashSet<>();

        for (GrantedAuthority authority : authorities) {
            reachableRoles.add(authority);
            Set<String> additionalReachableRoles = this.rolesReachableInOneOrMoreSteps.get(authority.getAuthority());

            if (additionalReachableRoles != null) {
                for (String additionalReachableRole : additionalReachableRoles) {
                    reachableRoles.add(new SimpleGrantedAuthority(additionalReachableRole));
                }
            }
        }

        return new ArrayList<>(reachableRoles);
    }

    private Map<String, Set<String>> buildRolesReachableInOneOrMoreSteps(String roleHierarchyRepresentation) {
        Map<String, Set<String>> rolesReachableInOneStepMap = buildRolesReachableInOneStep(roleHierarchyRepresentation);
        Map<String, Set<String>> rolesReachableInOneOrMoreStepsMap = new HashMap<>();

        for (String role : rolesReachableInOneStepMap.keySet()) {
            Set<String> rolesToVisitSet = new HashSet<>(rolesReachableInOneStepMap.get(role));
            Set<String> visitedRolesSet = new HashSet<>();

            while (!rolesToVisitSet.isEmpty()) {
                String aRole = rolesToVisitSet.iterator().next();
                rolesToVisitSet.remove(aRole);
                visitedRolesSet.add(aRole);

                Set<String> newReachableRoles = rolesReachableInOneStepMap.get(aRole);
                if (newReachableRoles != null) {
                    for (String newReachableRole : newReachableRoles) {
                        if (!visitedRolesSet.contains(newReachableRole)) {
                            rolesToVisitSet.add(newReachableRole);
                        }
                    }
                }
            }

            rolesReachableInOneOrMoreStepsMap.put(role, visitedRolesSet);
        }

        return rolesReachableInOneOrMoreStepsMap;
    }

    private Map<String, Set<String>> buildRolesReachableInOneStep(String roleHierarchyRepresentation) {
        Map<String, Set<String>> rolesReachableInOneStepMap = new HashMap<>();

        String[] lines = roleHierarchyRepresentation.split(System.lineSeparator());
        for (String line : lines) {
            String trimmedLine = line.trim();
            if (trimmedLine.isEmpty()) {
                continue;
            }

            String[] roles = trimmedLine.split(">");
            if (roles.length < 2) {
                continue;
            }

            String higherRole = roles[0].trim();
            for (int i = 1; i < roles.length; i++) {
                String lowerRole = roles[i].trim();
                Set<String> rolesReachableInOneStepSet = rolesReachableInOneStepMap.computeIfAbsent(
                        higherRole, k -> new HashSet<>());
                rolesReachableInOneStepSet.add(lowerRole);
                higherRole = lowerRole;
            }
        }

        return rolesReachableInOneStepMap;
    }

    @Override
    public String toString() {
        return "RoleHierarchyImpl[roles=" + this.rolesReachableInOneOrMoreSteps.keySet() + "]";
    }
}
