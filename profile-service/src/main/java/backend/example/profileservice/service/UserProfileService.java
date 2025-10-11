package backend.example.profileservice.service;

import backend.example.profileservice.dto.request.ProfileCreationRequest;
import backend.example.profileservice.dto.request.UpdateProfileRequest;
import backend.example.profileservice.dto.response.PageResponse;
import backend.example.profileservice.dto.response.UserProfileResponse;

import java.util.List;

public interface UserProfileService {
    UserProfileResponse create(ProfileCreationRequest request);

    UserProfileResponse update(UpdateProfileRequest request);

    UserProfileResponse getMyProfile();

    UserProfileResponse getProfileByUserId(String userId);

    UserProfileResponse getProfileById(String id);

    UserProfileResponse updateAvatar(String avatarUrl);

    PageResponse<List<UserProfileResponse>> getAllProfiles(int page, int size);
    PageResponse<List<UserProfileResponse>> searchProfiles(int page, int size, String keyword, String ... sort);


}
