package com.example.basicsecuirity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "user-table")
public class User {
    @Id
    private Long user_id;
    private String userName;
    private String password;
}
