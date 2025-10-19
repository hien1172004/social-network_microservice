package backend.example.notificationservice.controller;



import backend.example.event.dto.NotificationEvent;
import backend.example.notificationservice.dto.request.Recipient;
import backend.example.notificationservice.dto.request.SendEmailRequest;
import backend.example.notificationservice.service.EmailService;
import backend.example.notificationservice.service.NotificationService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class NotificationController {

    NotificationService notificationService;

    @KafkaListener(topics = "notification-delivery")
    public void listenNotification(NotificationEvent event) {
        log.info("Received Kafka event: {}", event);
        notificationService.handleNotification(event);
    }
}