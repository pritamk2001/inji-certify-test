package io.mosip.certify.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class VCApiKeyAuthFilterTest {

    @InjectMocks
    private VCApiKeyAuthFilter filter;

    @Mock
    private FilterChain filterChain;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private static final String SERVLET_PATH = "/v1/certify";
    private static final String VALID_API_KEY = "test-api-key";

    @Before
    public void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        ReflectionTestUtils.setField(filter, "servletPath", SERVLET_PATH);
        ReflectionTestUtils.setField(filter, "apiKeysConfig", VALID_API_KEY + ",other-key");
        SecurityContextHolder.clearContext();
    }

    @Test
    public void shouldFilterForVCApiCredentialsIssueUrl() {
        request.setRequestURI("/v1/certify/vc-api/credentials/issue");
        assertFalse(filter.shouldNotFilter(request));
    }

    @Test
    public void shouldFilterForVCApiStatusUrl() {
        request.setRequestURI("/v1/certify/vc-api/status");
        assertFalse(filter.shouldNotFilter(request));
    }

    @Test
    public void shouldNotFilterForIssuanceCredentialUrl() {
        request.setRequestURI("/v1/certify/issuance/credential");
        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    public void shouldNotFilterForOAuthTokenUrl() {
        request.setRequestURI("/v1/certify/oauth/token");
        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    public void shouldNotFilterForHealthUrl() {
        request.setRequestURI("/health");
        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    public void whenValidApiKey_shouldAuthenticateAndContinueChain() throws ServletException, IOException {
        request.setRequestURI(SERVLET_PATH + "/vc-api/credentials/issue");
        request.addHeader(VCApiKeyAuthFilter.API_KEY_HEADER, VALID_API_KEY);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertEquals(200, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void whenMissingApiKey_shouldReturnUnauthorized() throws ServletException, IOException {
        request.setRequestURI(SERVLET_PATH + "/vc-api/credentials/issue");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertEquals(401, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void whenInvalidApiKey_shouldReturnUnauthorized() throws ServletException, IOException {
        request.setRequestURI(SERVLET_PATH + "/vc-api/credentials/issue");
        request.addHeader(VCApiKeyAuthFilter.API_KEY_HEADER, "wrong-key");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertEquals(401, response.getStatus());
    }

    @Test
    public void whenApiKeyHasSurroundingWhitespace_shouldAcceptTrimmedKey() throws ServletException, IOException {
        ReflectionTestUtils.setField(filter, "apiKeysConfig", " " + VALID_API_KEY + " ");
        request.setRequestURI(SERVLET_PATH + "/vc-api/credentials/issue");
        request.addHeader(VCApiKeyAuthFilter.API_KEY_HEADER, VALID_API_KEY);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertEquals(200, response.getStatus());
    }
}
