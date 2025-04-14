package SecurityApplication.DTO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank(message = "Username cannot be blank")
    private String username;

    @NotBlank(message = "Password cannot be blank")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;

    @Override
    public String toString() {
        return "LoginRequest [username=" + username + "]";
    }
}
