package com.example.security.service;

import com.example.security.model.AppUser;
import com.example.security.model.Role;

import java.util.List;

public interface AppUserService {

    AppUser saveAppUser(AppUser appUser);
    Role saveRole(Role role);
    void addRoleToAppUser(String username, String roleName);
    AppUser getAppUser(String username);
    List<AppUser> getAppUsers();
}
