package SecurityApplication.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.util.Date;

@Data
@AllArgsConstructor
public class LoginResponse {

    private String token;

    private Date accessTokenExpiration;

    private String username;

}
