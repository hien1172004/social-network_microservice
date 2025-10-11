package backend.example.profileservice.service.impl;

import backend.example.profileservice.dto.request.ProfileCreationRequest;
import backend.example.profileservice.dto.request.UpdateProfileRequest;
import backend.example.profileservice.dto.response.PageResponse;
import backend.example.profileservice.dto.response.UserProfileResponse;
import backend.example.profileservice.entity.UserProfile;
import backend.example.profileservice.mapper.UserMapper;
import backend.example.profileservice.repository.UserRepository;
import backend.example.profileservice.service.BaseRedisService;
import backend.example.profileservice.service.UserProfileService;
import backend.example.profileservice.exception.AppException;
import backend.example.profileservice.exception.ErrorCode;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class UserProfileServiceImpl implements UserProfileService {
    UserMapper userMapper;
    UserRepository userRepository;
    private final BaseRedisService<String, String, Object> baseRedisService;
    public static final String USER_PROFILE_BY_ID = "USER_PROFILE:ID:";
    public static final String USER_PROFILE_BY_USERID = "USER_PROFILE:USERID:";
    @Override
    public UserProfileResponse create(ProfileCreationRequest request) {
        UserProfile userProfile = userMapper.toUserProfile(request);
        userRepository.save(userProfile);
        return userMapper.toUserProfileResponse(userProfile);
    }

    @Override
    public UserProfileResponse update(UpdateProfileRequest request) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        String userId = authentication.getName();
        UserProfile user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        userMapper.update(user, request);
        userRepository.save(user);

        // 🧹 Xóa cache
        baseRedisService.delete(USER_PROFILE_BY_USERID + userId);
        baseRedisService.delete(USER_PROFILE_BY_ID + user.getId());

        return userMapper.toUserProfileResponse(user);
    }

    @Override
    public UserProfileResponse getMyProfile() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUserId = authentication.getName();
        if (currentUserId == null) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        
        UserProfile profile = userRepository.findByUserId(currentUserId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
        
        return userMapper.toUserProfileResponse(profile);
    }

    @Override
    public UserProfileResponse getProfileByUserId(String userId) {
        String cacheKey = USER_PROFILE_BY_USERID + userId;

        // 1️⃣ Kiểm tra cache
        UserProfileResponse cached = (UserProfileResponse) baseRedisService.get(cacheKey);
        if (cached != null) {
            log.info("Cache hit for userId: {}", userId);
            return cached;
        }
        // Lấy từ DB
        UserProfile profile = userRepository.findByUserId(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
        UserProfileResponse response = userMapper.toUserProfileResponse(profile);

        // Lưu vào cache (TTL: 10 phút)
        baseRedisService.set(cacheKey, response);
        baseRedisService.setTimeToLive(cacheKey, 600); // 600 giây = 10 phút

        log.info("Cache miss for userId: {}, data stored", userId);
        return response;
    }

    @Override
    public UserProfileResponse getProfileById(String id) {
        String cacheKey = USER_PROFILE_BY_ID + id;

        // 1️⃣ Kiểm tra cache
        UserProfileResponse cached = (UserProfileResponse) baseRedisService.get(cacheKey);
        if (cached != null) {
            log.info("Cache hit for userId: {}", id);
            return cached;
        }
        // Lấy từ DB
        UserProfile profile = userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
        UserProfileResponse response = userMapper.toUserProfileResponse(profile);

        // Lưu vào cache (TTL: 10 phút)
        baseRedisService.set(cacheKey, response);
        baseRedisService.setTimeToLive(cacheKey, 600); // 600 giây = 10 phút

        log.info("Cache miss for userId: {}, data stored", id);
        return response;
    }

    @Override
    public UserProfileResponse updateAvatar(String avatarUrl) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUserId = authentication.getName();
        if (currentUserId == null) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        
        UserProfile profile = userRepository.findByUserId(currentUserId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
        
        profile.setAvatar(avatarUrl);
        UserProfile updatedProfile = userRepository.save(profile);
        
        return userMapper.toUserProfileResponse(updatedProfile);
    }

    @Override
    public PageResponse<List<UserProfileResponse>> getAllProfiles(int page, int size) {
        page = Math.max(page - 1, 0);
        var pageable = PageRequest.of(page, size);
        var result = userRepository.findAll(pageable);

        return PageResponse.<List<UserProfileResponse>>builder()
                .items(result.getContent()
                        .stream()
                        .map(userMapper::toUserProfileResponse)
                        .toList())
                .totalElements(result.getTotalElements())
                .totalPages(result.getTotalPages())
                .pageNo(page)
                .pageSize(size)
                .build();
    }

    @Override
    public PageResponse<List<UserProfileResponse>> searchProfiles(int pageNo, int pageSize, String keyword, String... sorts) {
        int page = Math.max(pageNo - 1, 0);
        List<Sort.Order> orders = new ArrayList<>();
        for(String sortBy : sorts) {
            Pattern pattern = Pattern.compile("(\\w+?)(:)(.*)");
            Matcher matcher = pattern.matcher(sortBy);
            if(matcher.find()) {
                if(matcher.group(3).equalsIgnoreCase("asc")){
                    orders.add(new Sort.Order(Sort.Direction.ASC, matcher.group(1)));
                }
                else if(matcher.group(3).equalsIgnoreCase("desc")){
                    orders.add(new Sort.Order(Sort.Direction.DESC, matcher.group(1)));
                }
            }
        }
        Pageable pageable = PageRequest.of(page, pageSize, Sort.by(orders));
        var result = userRepository.searchByKeyword(keyword, pageable);

        return PageResponse.<List<UserProfileResponse>>builder()
                .items(result.getContent()
                        .stream()
                        .map(userMapper::toUserProfileResponse)
                        .toList())
                .totalElements(result.getTotalElements())
                .totalPages(result.getTotalPages())
                .pageNo(page)
                .pageSize(pageSize)
                .build();
    }


}
