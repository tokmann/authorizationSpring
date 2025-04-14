package SecurityApplication.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Date;

@Data
@AllArgsConstructor
public class AuthResponse {

    private boolean authenticated;

    private Date accessTokenExpiration;

    private String username;

    private Long id;
}
