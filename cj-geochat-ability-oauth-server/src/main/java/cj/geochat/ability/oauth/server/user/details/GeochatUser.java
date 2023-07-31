package cj.geochat.ability.oauth.server.user.details;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;

public class GeochatUser extends User {
    private static final long serialVersionUID = 1L;
    String account;

    public GeochatUser(String user, String account, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(user, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.account = account;
    }

    public GeochatUser( String user,String account, String password, Collection<? extends GrantedAuthority> authorities) {
        super(user, password, authorities);
        this.account = account;
    }

    public static GeochatUserBuilder withUserAndAccount(String user, String account) {
        return geochatBuilder().username(user).account(account);
    }

    public static GeochatUserBuilder geochatBuilder() {
        return new GeochatUserBuilder();
    }

    public String getAccount() {
        return account;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getClass().getName()).append(" [");
        sb.append("Username=").append(this.getUsername()).append(", ");
        sb.append("Account=").append(this.account).append(", ");
        sb.append("Password=[PROTECTED], ");
        sb.append("Enabled=").append(this.isEnabled()).append(", ");
        sb.append("AccountNonExpired=").append(this.isAccountNonExpired()).append(", ");
        sb.append("credentialsNonExpired=").append(this.isCredentialsNonExpired()).append(", ");
        sb.append("AccountNonLocked=").append(this.isAccountNonLocked()).append(", ");
        sb.append("Granted Authorities=").append(this.getAuthorities()).append("]");
        return sb.toString();
    }

    public static final class GeochatUserBuilder {
        private String username;
        private String account;
        private String password;
        private List<GrantedAuthority> authorities = new ArrayList();
        private boolean accountExpired;
        private boolean accountLocked;
        private boolean credentialsExpired;
        private boolean disabled;
        private Function<String, String> passwordEncoder = (password) -> {
            return password;
        };

        private GeochatUserBuilder() {
        }

        public GeochatUserBuilder username(String username) {
            Assert.notNull(username, "username cannot be null");
            this.username = username;
            return this;
        }

        public GeochatUserBuilder account(String account) {
            Assert.notNull(account, "account cannot be null");
            this.account = account;
            return this;
        }

        public GeochatUserBuilder password(String password) {
            Assert.notNull(password, "password cannot be null");
            this.password = password;
            return this;
        }

        public GeochatUserBuilder passwordEncoder(Function<String, String> encoder) {
            Assert.notNull(encoder, "encoder cannot be null");
            this.passwordEncoder = encoder;
            return this;
        }

        public GeochatUserBuilder roles(String... roles) {
            List<GrantedAuthority> authorities = new ArrayList(roles.length);
            String[] var3 = roles;
            int var4 = roles.length;

            for (int var5 = 0; var5 < var4; ++var5) {
                String role = var3[var5];
                Assert.isTrue(!role.startsWith("ROLE_"), () -> {
                    return role + " cannot start with ROLE_ (it is automatically added)";
                });
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }

            return this.authorities((Collection) authorities);
        }

        public GeochatUserBuilder authorities(GrantedAuthority... authorities) {
            Assert.notNull(authorities, "authorities cannot be null");
            return this.authorities((Collection) Arrays.asList(authorities));
        }

        public GeochatUserBuilder authorities(Collection<? extends GrantedAuthority> authorities) {
            Assert.notNull(authorities, "authorities cannot be null");
            this.authorities = new ArrayList(authorities);
            return this;
        }

        public GeochatUserBuilder authorities(String... authorities) {
            Assert.notNull(authorities, "authorities cannot be null");
            return this.authorities((Collection) AuthorityUtils.createAuthorityList(authorities));
        }

        public GeochatUserBuilder accountExpired(boolean accountExpired) {
            this.accountExpired = accountExpired;
            return this;
        }

        public GeochatUserBuilder accountLocked(boolean accountLocked) {
            this.accountLocked = accountLocked;
            return this;
        }

        public GeochatUserBuilder credentialsExpired(boolean credentialsExpired) {
            this.credentialsExpired = credentialsExpired;
            return this;
        }

        public GeochatUserBuilder disabled(boolean disabled) {
            this.disabled = disabled;
            return this;
        }

        public UserDetails build() {
            String encodedPassword = (String) this.passwordEncoder.apply(this.password);
            return new GeochatUser(this.username,this.account,  encodedPassword, !this.disabled, !this.accountExpired, !this.credentialsExpired, !this.accountLocked, this.authorities);
        }
    }
}
