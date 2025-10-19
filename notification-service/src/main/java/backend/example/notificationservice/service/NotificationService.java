package backend.example.notificationservice.service;

import backend.example.event.dto.NotificationEvent;
import backend.example.notificationservice.dto.request.EmailRequest;
import backend.example.notificationservice.dto.request.Recipient;
import backend.example.notificationservice.dto.request.SendEmailRequest;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class NotificationService {

    EmailService emailService;
//    PushService pushService; // giả sử bạn có service gửi push

    public void handleNotification(NotificationEvent event) {
        log.info("Processing notification: {}", event);

        switch (event.getChannel().toUpperCase()) {
            case "EMAIL" -> sendEmail(event);
//            case "PUSH" -> sendPush(event);
            default -> log.warn("Unknown channel: {}", event.getChannel());
        }
    }

    private void sendEmail(NotificationEvent event) {
        SendEmailRequest request = SendEmailRequest.builder()
                .to(Recipient.builder()
                        .email(event.getRecipient())
                        .build())
                .subject(event.getSubject())
                .htmlContent(renderTemplate(event.getTemplateCode(), event.getParam()))
                .build();

        emailService.sendEmail(request);
        log.info("Email sent to {}", event.getRecipient());
    }

//    private void sendPush(NotificationEvent event) {
//        // PushService giả lập, bạn tùy chỉnh theo hệ thống push của bạn
//        pushService.sendPush(event.getRecipient(), event.getSubject(), event.getBody());
//        log.info("Push notification sent to {}", event.getRecipient());
//    }

    // Render template dựa trên templateCode và param
    private String renderTemplate(String templateCode, java.util.Map<String, Object> param) {
        // Ví dụ đơn giản: chèn ${username} và ${link} vào nội dung
        return switch (templateCode) {
            case "VERIFY_EMAIL" -> "<p>Xin chào " + param.get("username") +
                    ", vui lòng xác nhận email bằng cách click <a href='" + param.get("link") + "'>vào đây</a></p>";
            case "CHANGE_PASSWORD" -> "<p>Xin chào " + param.get("username") +
                    ", bạn có thể đổi mật khẩu tại <a href='" + param.get("link") + "'>đây</a></p>";
            default -> param.getOrDefault("body", "").toString();
        };
    }
}
