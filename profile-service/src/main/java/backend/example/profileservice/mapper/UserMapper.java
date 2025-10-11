package backend.example.profileservice.mapper;

import backend.example.profileservice.dto.request.ProfileCreationRequest;
import backend.example.profileservice.dto.request.UpdateProfileRequest;
import backend.example.profileservice.dto.response.UserProfileResponse;
import backend.example.profileservice.entity.UserProfile;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserProfile toUserProfile(ProfileCreationRequest request);

    UserProfileResponse toUserProfileResponse(UserProfile profile);

    void update(@MappingTarget UserProfile entity, UpdateProfileRequest request);
}

