package SecurityApplication.DTO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank(message = "Username cannot be empty")
    private String username;

    @NotBlank(message = "Password cannot be empty")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;

    @Override
    public String toString() {
        return "RegisterRequest [username=" + username + "]";
    }

}
