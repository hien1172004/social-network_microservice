package backend.example.profileservice.controller;

import backend.example.profileservice.dto.request.ApiResponse;
import backend.example.profileservice.dto.request.ProfileCreationRequest;
import backend.example.profileservice.dto.response.UserProfileResponse;
import backend.example.profileservice.service.UserProfileService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class InternalController {
    UserProfileService userProfileService;

    @PostMapping("/create-default-profile")
    ApiResponse<UserProfileResponse> createUserDefaultProfile(@RequestBody ProfileCreationRequest request) {
        var profile = userProfileService.create(request);
        return ApiResponse.<UserProfileResponse>builder().
                result(profile).
                build();
    }


}
