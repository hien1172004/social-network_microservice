package backend.example.identityservice.service;

import backend.example.identityservice.dto.request.SignUpDTO;
import backend.example.identityservice.dto.request.UserCreationRequest;
import backend.example.identityservice.dto.request.UserUpdateRequest;
import backend.example.identityservice.dto.response.UserResponse;

import java.util.List;

public interface UserService {
    // User tự đăng ký
    String signUp(SignUpDTO request);

    // Xác thực email (activation)
    String verifyEmail(String token);

    // Lấy thông tin user hiện tại
    UserResponse getMyInfo();

    // Admin hoặc service khác tạo user
    UserResponse createUser(UserCreationRequest request);

    // Admin cập nhật user
    UserResponse updateUser(String userId, UserUpdateRequest request);

    // Admin xóa user
    void deleteUser(String userId);

    // Admin lấy danh sách user
    List<UserResponse> getUsers();

    // Admin lấy user theo ID
    UserResponse getUser(String userId);
}
