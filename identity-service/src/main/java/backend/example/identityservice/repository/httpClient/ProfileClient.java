package backend.example.identityservice.repository.httpClient;

import backend.example.identityservice.config.AuthenticationRequestInterceptor;
import backend.example.identityservice.dto.request.ApiResponse;
import backend.example.identityservice.dto.request.ProfileCreationRequest;
import backend.example.identityservice.dto.response.UserProfileResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "profile-service", url = "${app.services.profile}",
configuration = {AuthenticationRequestInterceptor.class})
public interface ProfileClient {
    @PostMapping(value = "internal/create-default-profile", produces = MediaType.APPLICATION_JSON_VALUE)
    ApiResponse<UserProfileResponse> createUserDefaultProfile(@RequestBody ProfileCreationRequest request);
}
