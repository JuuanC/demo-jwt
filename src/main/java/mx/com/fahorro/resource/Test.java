package mx.com.fahorro.resource;

import io.smallrye.jwt.build.Jwt;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import org.eclipse.microprofile.jwt.Claims;
import java.util.Arrays;
import java.util.HashSet;

@Path("")
public class Test {


    @GET
    @Path("generar")
    public String generar(){
        String token =
                Jwt.issuer("https://example.com/issuer")
                        .upn("jdoe@quarkus.io")
                        .groups(new HashSet<>(Arrays.asList("User", "Admin")))
                        .claim(Claims.birthdate.name(), "2001-07-13")
                        .sign();
        return token;
    }

    @GET
    @Path("Validar")
    @RolesAllowed("Admin")
    public boolean validar(){
        return true;
    }
}
