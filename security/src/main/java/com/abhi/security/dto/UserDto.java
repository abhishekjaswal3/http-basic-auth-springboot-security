package com.abhi.security.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {

    @NotBlank(message = "userName cannot ne null or blank")
    private String userName;
    private String email;

    @NotBlank(message = "password cannot ne null or blank")
    private String password;

    @NotEmpty(message = "Items roles cannot be empty")
    private List<@NotBlank(message = "roles cannot be blank") String> roles;
}
