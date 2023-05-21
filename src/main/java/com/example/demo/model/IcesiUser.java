package com.example.demo.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;

import javax.persistence.*;


import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
public class IcesiUser {

    @Id
    @GeneratedValue
    @GenericGenerator(name = "uuid", strategy = "uuid2")
    @Type(type = "pg-uuid")
    private UUID icesiUserId;

    private String firstName;
    private String lastName;
    private String icesiCode;
    private boolean active;
    private String email;
    private String mobilePhone;
    private String password;
    private String address;
    private int age;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private IcesiRole role;


}
