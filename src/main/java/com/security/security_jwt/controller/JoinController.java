package com.security.security_jwt.controller;

import com.security.security_jwt.dto.JoinDTO;
import com.security.security_jwt.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {

    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinPorces(JoinDTO dto) {

        joinService.joinProces(dto);

        return "ok";
    }
}
