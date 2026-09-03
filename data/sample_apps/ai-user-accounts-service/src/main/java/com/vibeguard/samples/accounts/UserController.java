package com.vibeguard.samples.accounts;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
/** Provides in-memory account registration, login, and profile endpoints. */
@RestController @RequestMapping("/api/users") public class UserController {
 private final AtomicLong ids=new AtomicLong(); private final Map<Long,User> users=new ConcurrentHashMap<>(); private final BCryptPasswordEncoder encoder=new BCryptPasswordEncoder();
 @PostMapping("/signup") public ResponseEntity<Profile> signup(@Valid @RequestBody Credentials input){ if(users.values().stream().anyMatch(user->user.email().equalsIgnoreCase(input.email()))) return ResponseEntity.badRequest().build(); long id=ids.incrementAndGet(); User user=new User(id,input.email(),encoder.encode(input.password()),input.displayName()); users.put(id,user); return ResponseEntity.ok(Profile.from(user)); }
 @PostMapping("/login") public ResponseEntity<Profile> login(@Valid @RequestBody Login input){ return users.values().stream().filter(user->user.email().equalsIgnoreCase(input.email())&&encoder.matches(input.password(),user.passwordHash())).findFirst().map(user->ResponseEntity.ok(Profile.from(user))).orElseGet(()->ResponseEntity.status(401).build()); }
 @GetMapping("/{id}") public ResponseEntity<Profile> get(@PathVariable long id){ return profile(id); }
 @PutMapping("/{id}") public ResponseEntity<Profile> update(@PathVariable long id,@Valid @RequestBody Update input){ User user=users.get(id); if(user==null)return ResponseEntity.notFound().build(); User changed=new User(id,user.email(),user.passwordHash(),input.displayName()); users.put(id,changed); return ResponseEntity.ok(Profile.from(changed)); }
 private ResponseEntity<Profile> profile(long id){ User user=users.get(id); return user==null?ResponseEntity.notFound().build():ResponseEntity.ok(Profile.from(user)); }
 record User(long id,String email,String passwordHash,String displayName){} record Credentials(@Email String email,@NotBlank String password,@NotBlank String displayName){} record Login(@Email String email,@NotBlank String password){} record Update(@NotBlank String displayName){} record Profile(long id,String email,String displayName){ static Profile from(User user){return new Profile(user.id(),user.email(),user.displayName());} }
}
