package com.dollop.app.security.core;

import com.dollop.app.security.core.model.SecurityErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.util.Assert;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Utility component responsible for writing a structured JSON error response to an
 * {@link HttpServletResponse} from within the Spring Security filter chain.
 *
 * <p>Spring Security's filter chain operates below the Spring MVC dispatcher servlet.
 * Exceptions thrown inside filters (such as {@code JwtAuthenticationFilter}) cannot be
 * handled by {@code @ControllerAdvice} or {@code @ExceptionHandler} — those mechanisms
 * only apply to requests that reach the servlet layer. This writer provides a
 * consistent, JSON-formatted error response for security-related failures that are
 * intercepted at the filter level.</p>
 *
 * <h3>Response Format</h3>
 * <p>All responses use the {@link SecurityErrorResponse} model, which is serialised to
 * JSON by the injected {@link ObjectMapper}. The response always has:</p>
 * <ul>
 *   <li>Content-Type: {@code application/json;charset=UTF-8}</li>
 *   <li>Cache-Control: {@code no-store, no-cache} (prevents clients from caching
 *       error responses that may contain sensitive information)</li>
 *   <li>Body: {@link SecurityErrorResponse} serialised as JSON</li>
 * </ul>
 *
 * <h3>Usage</h3>
 * <p>Inject this component into filter classes that need to write error responses.
 * It is registered as a Spring bean by {@code SecurityCoreAutoConfiguration}.</p>
 *
 * <h3>Thread Safety</h3>
 * <p>This class is stateless and thread-safe. The {@link ObjectMapper} is shared but
 * configured as thread-safe by Spring Boot's auto-configuration.</p>
 *
 * @see SecurityErrorResponse
 * @see com.dollop.app.security.core.exception.SecurityFrameworkException
 * @since Phase 7.4
 */
@Slf4j
public class SecurityErrorResponseWriter {

    private static final String CACHE_CONTROL_NO_STORE = "no-store, no-cache";

    private final ObjectMapper objectMapper;

    /**
     * Constructs the writer with the shared Jackson {@link ObjectMapper}.
     *
     * @param objectMapper the Jackson object mapper used to serialise
     *                     {@link SecurityErrorResponse} to JSON; must not be {@code null}
     * @throws IllegalArgumentException if {@code objectMapper} is {@code null}
     */
    public SecurityErrorResponseWriter(ObjectMapper objectMapper) {
        Assert.notNull(objectMapper, "objectMapper must not be null");
        this.objectMapper = objectMapper;
    }

    /**
     * Writes a {@link SecurityErrorResponse} JSON body to the given
     * {@link HttpServletResponse} with the specified HTTP status code and error message.
     *
     * <p>This method commits the HTTP response. Once called, the response cannot be
     * further modified by downstream filters or handlers. The caller must ensure this
     * method is invoked only when the response has not already been committed.</p>
     *
     * <p>If serialisation fails (e.g., due to an unrecoverable {@link ObjectMapper} error),
     * the exception is logged at ERROR level and rethrown as an {@link IOException}.
     * The calling filter must propagate or handle this appropriately.</p>
     *
     * @param response  the HTTP response to write to; must not be {@code null} and must
     *                  not have been committed already
     * @param status    the HTTP status code to set (e.g., 401, 403, 423)
     * @param errorText a short error category string (e.g., "Unauthorized", "Forbidden")
     *                  corresponding to the HTTP status
     * @param message   a human-readable explanation of the error; must be safe to expose
     *                  to the client (no internal stack trace, no system paths)
     * @param path      the request URI that triggered the error; typically obtained from
     *                  {@code request.getRequestURI()}
     * @throws IOException if the response output stream cannot be written to, or if
     *                     Jackson serialisation fails
     */
    public void write(
            HttpServletResponse response,
            int status,
            String errorText,
            String message,
            String path) throws IOException {

        SecurityErrorResponse errorResponse = SecurityErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(status)
                .error(errorText)
                .message(message)
                .path(path)
                .build();

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", CACHE_CONTROL_NO_STORE);

        try {
            objectMapper.writeValue(response.getOutputStream(), errorResponse);
        } catch (IOException ex) {
            log.error("Failed to write security error response to output stream " +
                    "[status={}, path={}]", status, path, ex);
            throw ex;
        }
    }

    /**
     * Convenience overload that derives the {@code errorText} label from the
     * HTTP status code using the standard HTTP reason phrase mapping for the
     * status codes most commonly produced by the security filter chain.
     *
     * <p>Supported status → reason phrase mappings:</p>
     * <ul>
     *   <li>401 → "Unauthorized"</li>
     *   <li>403 → "Forbidden"</li>
     *   <li>423 → "Locked"</li>
     *   <li>Any other → "Error"</li>
     * </ul>
     *
     * @param response the HTTP response to write to
     * @param status   the HTTP status code
     * @param message  a human-readable explanation of the error
     * @param path     the request URI that triggered the error
     * @throws IOException if writing to the response output stream fails
     */
    public void write(
            HttpServletResponse response,
            int status,
            String message,
            String path) throws IOException {

        write(response, status, resolveReasonPhrase(status), message, path);
    }

    /**
     * Maps an HTTP status code to its standard reason phrase for use as the
     * {@code error} field in the {@link SecurityErrorResponse} body.
     *
     * @param status the HTTP status code
     * @return the reason phrase string
     */
    private String resolveReasonPhrase(int status) {
        return switch (status) {
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 423 -> "Locked";
            default  -> "Error";
        };
    }
}
