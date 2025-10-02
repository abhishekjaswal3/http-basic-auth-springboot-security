package com.abhi.security.entity;


import com.abhi.security.utility.ListToStringConverter;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @NonNull
    private String userName;
    private String email;
    @NonNull
    private String password;
    @Convert(converter = ListToStringConverter.class)
    private List<String> roles;
}
