package backend.example.notificationservice.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SendEmailRequest {
    @NotNull(message = "Recipient cannot be null")
    @Valid
    Recipient to;
    
    @NotBlank(message = "Subject cannot be blank")
    String subject;
    
    @NotBlank(message = "HTML content cannot be blank")
    String htmlContent;
}