package com.security.security_jwt.service;

import com.security.security_jwt.dto.JoinDTO;
import com.security.security_jwt.entity.UserEntity;
import com.security.security_jwt.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProces(JoinDTO dto) {
        Boolean isExist = userRepository.existsByUsername(dto.getUsername());

        if(isExist) {
            return;
        }

        UserEntity data = new UserEntity();
        data.setUsername(dto.getUsername());
        data.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
        data.setRole("ROLE_ADMIN");
        userRepository.save(data);
    }

}
