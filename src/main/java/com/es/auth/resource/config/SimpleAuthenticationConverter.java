package com.es.auth.resource.config;


import com.nimbusds.jose.shaded.json.JSONArray;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class CognitoAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final Converter<Jwt, Collection<SimpleGrantedAuthority>> authoritiesConverter = new JwtRolesConverter();

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<SimpleGrantedAuthority> authorities = authoritiesConverter.convert(jwt);
        return new JwtAuthenticationToken(jwt, authorities);
    }


    static class JwtRolesConverter implements Converter<Jwt, Collection<SimpleGrantedAuthority>> {

        @Override
        public List<SimpleGrantedAuthority> convert(Jwt jwt) {
            JSONArray roles = (JSONArray) jwt.getClaims().get(SecurityService.ROLES_CLAIM);

            return Optional.ofNullable(roles).stream()
                    .flatMap(Collection::stream)
                    .filter(Objects::nonNull)
                    .map(String.class::cast)
                    .map(role -> new SimpleGrantedAuthority(SecurityService.ROLE_PREFIX + role.toUpperCase()))
                    .toList();
        }
    }

}
