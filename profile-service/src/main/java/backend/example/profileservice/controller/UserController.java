package backend.example.profileservice.controller;

import backend.example.profileservice.dto.request.ApiResponse;
import backend.example.profileservice.dto.request.ProfileCreationRequest;
import backend.example.profileservice.dto.request.UpdateProfileRequest;
import backend.example.profileservice.dto.response.PageResponse;
import backend.example.profileservice.dto.response.UserProfileResponse;
import backend.example.profileservice.service.UserProfileService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserController {
    UserProfileService userProfileService;

    @PostMapping("/")
    ApiResponse<UserProfileResponse> createUser(@RequestBody ProfileCreationRequest profileCreationRequest) {
        var result = userProfileService.create(profileCreationRequest);
        return ApiResponse.<UserProfileResponse>builder()
                .result(result)
                .build();
    }

    @GetMapping("/my-profile")
    ApiResponse<UserProfileResponse> getMyProfile() {
        var result = userProfileService.getMyProfile();
        return ApiResponse.<UserProfileResponse>builder()
                .result(result)
                .build();
    }

    @GetMapping("/{id}")
    ApiResponse<UserProfileResponse> getUserProfileById(@PathVariable String id) {
        var result = userProfileService.getProfileById(id);
        return ApiResponse.<UserProfileResponse>builder()
                .result(result)
                .build();
    }

    @PutMapping("/")
    ApiResponse<UserProfileResponse> updateUser(@RequestBody UpdateProfileRequest request) {
        var result = userProfileService.update(request);
        return ApiResponse.<UserProfileResponse>builder()
                .result(result)
                .build();
    }

    @GetMapping
    public ApiResponse<?> getAllProfiles(
            @RequestParam(defaultValue = "1", required = false ) int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        var result = userProfileService.getAllProfiles(page, size);
        return ApiResponse.<PageResponse<?>>builder()
                .result(result)
                .build();
    }

    @GetMapping("/search")
    public ApiResponse<?> searchProfiles(
            @RequestParam(defaultValue = "1", required = false) int page,
            @RequestParam(defaultValue = "10", required = false) int size,
            @RequestParam (required = true) String keyword,
            @RequestParam(required = false, defaultValue = "createdDate:desc") String... sorts
    ) {
        var result = userProfileService.searchProfiles(page, size, keyword, sorts);
        return ApiResponse.<PageResponse<?>>builder()
                .result(result)
                .build();
    }
}
