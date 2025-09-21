pragma circom 2.1.6;

include "./utils/jwt.circom";
include "./circomlib/circuits/comparators.circom";
include "./circomlib/circuits/gates.circom";
include "./match_claim.circom";

template Main(max_msg_bytes, max_json_bytes, field_byte_len, n, k) {

    // #################### JWT signature verification ####################

    signal input message[max_msg_bytes]; // header + . + payload
    signal input modulus[k]; // Modulus from RSA public key (assumes e = 2^16 + 1)
    signal input signature[k];

    signal input message_padded_bytes; // length of the message including the padding
    signal input period_idx; // index of the period in the base64 encoded msg

    component jwt_verify = JWTVerify(max_msg_bytes, max_json_bytes, n, k);
    
    for (var i = 0; i < max_msg_bytes; i++) {
        jwt_verify.message[i] <== message[i];
    }

    for (var i = 0; i < k; i++) {
        jwt_verify.modulus[i] <== modulus[i];
        jwt_verify.signature[i] <== signature[i];
    }

    jwt_verify.message_padded_bytes <== message_padded_bytes;
    jwt_verify.period_idx <== period_idx;

    signal jwt_bytes[max_json_bytes];
    for (var i = 0; i < max_json_bytes; i++) {
        jwt_bytes[i] <== jwt_verify.jwt_bytes[i];
    }

    // #################### JWT claim predicates ####################

    // Compute the nested level of each position.
    component is_curly_bracket_l[max_json_bytes];
    component is_curly_bracket_r[max_json_bytes];
    signal object_nested_level[max_json_bytes + 1];
    object_nested_level[0] <== 0;
    for (var i = 0; i < max_json_bytes; i++) {
        is_curly_bracket_l[i] = IsZero();
        is_curly_bracket_r[i] = IsZero();
        is_curly_bracket_l[i].in <== jwt_bytes[i] - 123;
        is_curly_bracket_r[i].in <== jwt_bytes[i] - 125;
        object_nested_level[i + 1] <== object_nested_level[i] + is_curly_bracket_l[i].out - is_curly_bracket_r[i].out;
    }


    log("=== exp ===");
    var exp[6] = [34, 101, 120, 112, 34, 58];
    signal input exp_l;
    signal input exp_r;
    component match_exp_name = MatchClaimName(max_json_bytes, 6);
    match_exp_name.name <== exp;
    match_exp_name.json_bytes <== jwt_bytes;
    match_exp_name.l <== exp_l;
    match_exp_name.r <== exp_r;
    match_exp_name.object_nested_level <== object_nested_level;

    var exp_max_claim_byte_len = 31;
                            
    component reveal_exp = RevealClaimValue(max_json_bytes, exp_max_claim_byte_len, field_byte_len, 1);
    reveal_exp.json_bytes <== jwt_bytes;
    reveal_exp.l <== match_exp_name.value_l;
    reveal_exp.r <== match_exp_name.value_r;
                        
    signal input exp_value;
    log("exp_value = ", exp_value);
    log("reveal_exp.value = ", reveal_exp.value);                        
    exp_value === reveal_exp.value;


    log("=== email ===");
    var email[8] = [34, 101, 109, 97, 105, 108, 34, 58];
    signal input email_l;
    signal input email_r;
    component match_email_name = MatchClaimName(max_json_bytes, 8);
    match_email_name.name <== email;
    match_email_name.json_bytes <== jwt_bytes;
    match_email_name.l <== email_l;
    match_email_name.r <== email_r;
    match_email_name.object_nested_level <== object_nested_level;

    var email_max_claim_byte_len = 31;
                            
    component reveal_email = RevealDomainOnly(max_json_bytes, email_max_claim_byte_len, field_byte_len, 0);
    reveal_email.json_bytes <== jwt_bytes;
    reveal_email.l <== match_email_name.value_l;
    reveal_email.r <== match_email_name.value_r;
                        
    signal input email_value;
    log("email_value = ", email_value);
    log("reveal_email.value = ", reveal_email.value);                        
    email_value === reveal_email.value;


    log("=== family_name ===");
    var family_name[14] = [34, 102, 97, 109, 105, 108, 121, 95, 110, 97, 109, 101, 34, 58];
    signal input family_name_l;
    signal input family_name_r;
    component match_family_name_name = MatchClaimName(max_json_bytes, 14);
    match_family_name_name.name <== family_name;
    match_family_name_name.json_bytes <== jwt_bytes;
    match_family_name_name.l <== family_name_l;
    match_family_name_name.r <== family_name_r;
    match_family_name_name.object_nested_level <== object_nested_level;

    var family_name_max_claim_byte_len = 31;
                            
    component reveal_family_name = RevealClaimValue(max_json_bytes, family_name_max_claim_byte_len, field_byte_len, 0);
    reveal_family_name.json_bytes <== jwt_bytes;
    reveal_family_name.l <== match_family_name_name.value_l;
    reveal_family_name.r <== match_family_name_name.value_r;
                        
    signal input family_name_value;
    log("family_name_value = ", family_name_value);
    log("reveal_family_name.value = ", reveal_family_name.value);                        
    family_name_value === reveal_family_name.value;


    log("=== given_name ===");
    var given_name[13] = [34, 103, 105, 118, 101, 110, 95, 110, 97, 109, 101, 34, 58];
    signal input given_name_l;
    signal input given_name_r;
    component match_given_name_name = MatchClaimName(max_json_bytes, 13);
    match_given_name_name.name <== given_name;
    match_given_name_name.json_bytes <== jwt_bytes;
    match_given_name_name.l <== given_name_l;
    match_given_name_name.r <== given_name_r;
    match_given_name_name.object_nested_level <== object_nested_level;

    var given_name_max_claim_byte_len = 31;
                            
    component reveal_given_name = RevealClaimValue(max_json_bytes, given_name_max_claim_byte_len, field_byte_len, 0);
    reveal_given_name.json_bytes <== jwt_bytes;
    reveal_given_name.l <== match_given_name_name.value_l;
    reveal_given_name.r <== match_given_name_name.value_r;
                        
    signal input given_name_value;
    log("given_name_value = ", given_name_value);
    log("reveal_given_name.value = ", reveal_given_name.value);                        
    given_name_value === reveal_given_name.value;


    log("=== tenant_ctry ===");
    var tenant_ctry[14] = [34, 116, 101, 110, 97, 110, 116, 95, 99, 116, 114, 121, 34, 58];
    signal input tenant_ctry_l;
    signal input tenant_ctry_r;
    component match_tenant_ctry_name = MatchClaimName(max_json_bytes, 14);
    match_tenant_ctry_name.name <== tenant_ctry;
    match_tenant_ctry_name.json_bytes <== jwt_bytes;
    match_tenant_ctry_name.l <== tenant_ctry_l;
    match_tenant_ctry_name.r <== tenant_ctry_r;
    match_tenant_ctry_name.object_nested_level <== object_nested_level;

    var tenant_ctry_max_claim_byte_len = 31;
                            
    component reveal_tenant_ctry = RevealClaimValue(max_json_bytes, tenant_ctry_max_claim_byte_len, field_byte_len, 0);
    reveal_tenant_ctry.json_bytes <== jwt_bytes;
    reveal_tenant_ctry.l <== match_tenant_ctry_name.value_l;
    reveal_tenant_ctry.r <== match_tenant_ctry_name.value_r;
                        
    signal input tenant_ctry_value;
    log("tenant_ctry_value = ", tenant_ctry_value);
    log("reveal_tenant_ctry.value = ", reveal_tenant_ctry.value);                        
    tenant_ctry_value === reveal_tenant_ctry.value;


    log("=== tenant_region_scope ===");
    var tenant_region_scope[22] = [34, 116, 101, 110, 97, 110, 116, 95, 114, 101, 103, 105, 111, 110, 95, 115, 99, 111, 112, 101, 34, 58];
    signal input tenant_region_scope_l;
    signal input tenant_region_scope_r;
    component match_tenant_region_scope_name = MatchClaimName(max_json_bytes, 22);
    match_tenant_region_scope_name.name <== tenant_region_scope;
    match_tenant_region_scope_name.json_bytes <== jwt_bytes;
    match_tenant_region_scope_name.l <== tenant_region_scope_l;
    match_tenant_region_scope_name.r <== tenant_region_scope_r;
    match_tenant_region_scope_name.object_nested_level <== object_nested_level;

    var tenant_region_scope_max_claim_byte_len = 31;
                            
    component reveal_tenant_region_scope = RevealClaimValue(max_json_bytes, tenant_region_scope_max_claim_byte_len, field_byte_len, 0);
    reveal_tenant_region_scope.json_bytes <== jwt_bytes;
    reveal_tenant_region_scope.l <== match_tenant_region_scope_name.value_l;
    reveal_tenant_region_scope.r <== match_tenant_region_scope_name.value_r;
                        
    signal input tenant_region_scope_value;
    log("tenant_region_scope_value = ", tenant_region_scope_value);
    log("reveal_tenant_region_scope.value = ", reveal_tenant_region_scope.value);                        
    tenant_region_scope_value === reveal_tenant_region_scope.value;


    log("=== aud ===");
    var aud[6] = [34, 97, 117, 100, 34, 58];
    signal input aud_l;
    signal input aud_r;
    component match_aud_name = MatchClaimName(max_json_bytes, 6);
    match_aud_name.name <== aud;
    match_aud_name.json_bytes <== jwt_bytes;
    match_aud_name.l <== aud_l;
    match_aud_name.r <== aud_r;
    match_aud_name.object_nested_level <== object_nested_level;
    var aud_max_claim_byte_len = 62;
    component hash_reveal_aud = HashRevealClaimValue(max_json_bytes, aud_max_claim_byte_len, field_byte_len, 0);
    hash_reveal_aud.json_bytes <== jwt_bytes;
    hash_reveal_aud.l <== match_aud_name.value_l;
    hash_reveal_aud.r <== match_aud_name.value_r;
                        
    signal output aud_digest;
    aud_digest <== hash_reveal_aud.digest;

    log("=== auth_time ===");
    var auth_time[12] = [34, 97, 117, 116, 104, 95, 116, 105, 109, 101, 34, 58];
    signal input auth_time_l;
    signal input auth_time_r;
    component match_auth_time_name = MatchClaimName(max_json_bytes, 12);
    match_auth_time_name.name <== auth_time;
    match_auth_time_name.json_bytes <== jwt_bytes;
    match_auth_time_name.l <== auth_time_l;
    match_auth_time_name.r <== auth_time_r;
    match_auth_time_name.object_nested_level <== object_nested_level;
    var auth_time_max_claim_byte_len = 31;
    component hash_reveal_auth_time = HashRevealClaimValue(max_json_bytes, auth_time_max_claim_byte_len, field_byte_len, 1);
    hash_reveal_auth_time.json_bytes <== jwt_bytes;
    hash_reveal_auth_time.l <== match_auth_time_name.value_l;
    hash_reveal_auth_time.r <== match_auth_time_name.value_r;
                        
    signal output auth_time_digest;
    auth_time_digest <== hash_reveal_auth_time.digest;
}

component main { public [modulus, exp_value, email_value, family_name_value, given_name_value, tenant_ctry_value, tenant_region_scope_value ] } = Main(2048, 1536, 31, 121, 17);
