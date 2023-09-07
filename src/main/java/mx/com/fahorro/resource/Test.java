package mx.com.fahorro.resource;

import io.smallrye.jwt.build.Jwt;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;

@Path("")
@Produces({MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN})
public class Test {
    private static final Logger log = LoggerFactory.getLogger(Test.class);

    @Inject
    JsonWebToken jwt;

    @ConfigProperty(name = "token.expires")
    int tokenExpires;

    @GET
    @Path("/generar")
    public String generar(){
        return Jwt.issuer("https://example.com/issuer")
                .upn("jdoe@quarkus.io")
                .groups(new HashSet<>(Arrays.asList("User", "Admin")))
                .claim(Claims.azp, "4ef4325e")
                .claim(Claims.birthdate.name(), "2001-07-13")
                .expiresAt(Date.from(ZonedDateTime.now().plusSeconds(tokenExpires).toInstant()).toInstant())
                .sign();
    }


    @GET
    @Path("/validarRoles")
    @RolesAllowed({ "User", "Admin" })
    public Response validarAcceso(@Context SecurityContext ctx) {
        return Response.ok("Acceso correcto, bienvenido " + ctx.getUserPrincipal().getName()).build();
    }

    @GET
    @Path("/validar")
    public Response validar(@Context SecurityContext ctx) {

        log.info("Se procede a validar el token");
        if (ctx.getUserPrincipal() == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Token no proporcionado o inválido").build();
        }

        try {
            // Obtén el claim de expiración del token
            Long expEpoch = jwt.getClaim(Claims.exp.name());
            Date exp = new Date(expEpoch * 1000); // Convertir segundos a milisegundos

            // Compara la fecha de expiración con la hora actual
            if (exp.before(new Date())) {
                log.error("Token expirado");
                // Si el token ha expirado, retorna un 401
                return Response.status(Response.Status.UNAUTHORIZED).entity("Token expirado").build();
            }
        } catch (Exception e) {
            log.error("No se pudo verificar la expiración del token");
            // Si no podemos obtener el claim de expiración por alguna razón, también retornamos un 401
            return Response.status(Response.Status.UNAUTHORIZED).entity("No se pudo verificar la expiración del token").build();
        }

        log.info("Token válido");
        // Si todas las validaciones pasan
        return Response.status(Response.Status.OK).entity("Token válido").build();
    }

}
