# This file is a part of Julia. License is MIT: http://julialang.org/license

const urlmatcher = r"^(http[s]?|git|ssh)?(:\/\/)?((\w+)@)?([A-Za-z0-9\-\.]+)(:[0-9]+)?(.*)$"

function version()
    major = Ref{Cint}(0)
    minor = Ref{Cint}(0)
    patch = Ref{Cint}(0)
    ccall((:git_libgit2_version, :libgit2), Void,
          (Ptr{Cint}, Ptr{Cint}, Ptr{Cint}), major, minor, patch)
    return VersionNumber(major[], minor[], patch[])
end

isset(val::Integer, flag::Integer) = (val & flag == flag)
reset(val::Integer, flag::Integer) = (val &= ~flag)
toggle(val::Integer, flag::Integer) = (val |= flag)

function prompt(msg::AbstractString; default::AbstractString="", password::Bool=false)
    if is_windows() && password
        error("Command line prompt not supported for password entry on windows. Use winprompt instead")
    end
    msg = !isempty(default) ? msg*" [$default]:" : msg*":"
    uinput = if password
        Base.getpass(msg)
    else
        print(msg)
        chomp(readline(STDIN))
    end
    isempty(uinput) ? default : uinput
end

function features()
    feat = ccall((:git_libgit2_features, :libgit2), Cint, ())
    res = Consts.GIT_FEATURE[]
    for f in instances(Consts.GIT_FEATURE)
        isset(feat, Cuint(f)) && push!(res, f)
    end
    return res
end

# Windows authentication prompt
if is_windows()
    immutable CREDUI_INFO
        cbSize::UInt32
        parent::Ptr{Void}
        pszMessageText::Ptr{UInt16}
        pszCaptionText::Ptr{UInt16}
        banner::Ptr{Void}
    end

    const CREDUIWIN_GENERIC                 = 0x0001
    const CREDUIWIN_IN_CRED_ONLY            = 0x0020
    const CREDUIWIN_ENUMERATE_CURRENT_USER  = 0x0200

    const CRED_PACK_GENERIC_CREDENTIALS     = 0x0004

    const ERROR_SUCCESS                     = 0x0000
    const ERROR_CANCELLED                   = 0x04c7

    function winprompt(message, caption, default_username; prompt_username = true)
        # Step 1: Create an encrypted username/password bundle that will be used to set
        #         the default username (in theory could also provide a default password)
        credbuf = Array(UInt8, 1024)
        credbufsize = Ref{UInt32}(sizeof(credbuf))
        succeeded = ccall((:CredPackAuthenticationBufferW, "Credui.dll"), stdcall, Bool,
            (UInt32, Cwstring, Cwstring, Ptr{UInt8}, Ptr{UInt32}),
             CRED_PACK_GENERIC_CREDENTIALS, default_username, "", credbuf, credbufsize)
        @assert succeeded

        # Step 2: Create the actual dialog
        #      2.1: Set up the window
        messageArr = Base.cwstring(message)
        captionArr = Base.cwstring(caption)
        pfSave = Ref{Bool}(false)
        cred = Ref{CREDUI_INFO}(CREDUI_INFO(sizeof(CREDUI_INFO), C_NULL, pointer(messageArr), pointer(captionArr), C_NULL))
        dwflags = CREDUIWIN_GENERIC | CREDUIWIN_ENUMERATE_CURRENT_USER
        if !prompt_username
            # Disable setting anything other than default_username
            dwflags |= CREDUIWIN_IN_CRED_ONLY
        end
        authPackage = Ref{Culong}(0)
        outbuf_data = Ref{Ptr{Void}}(C_NULL)
        outbuf_size = Ref{Culong}(0)

        #      2.2: Do the actual request
        code = ccall((:CredUIPromptForWindowsCredentialsW, "Credui.dll"), stdcall, UInt32, (Ptr{CREDUI_INFO}, UInt32, Ptr{Culong},
            Ptr{Void}, Culong, Ptr{Ptr{Void}}, Ptr{Culong}, Ptr{Bool}, UInt32), cred, 0, authPackage, credbuf, credbufsize[],
            outbuf_data, outbuf_size, pfSave, dwflags)

        #      2.3: If that failed for any reason other than the user canceling, error out.
        #           If the user canceled, just return a nullable
        if code == ERROR_CANCELLED
            return Nullable{Tuple{String,String}}()
        elseif code != ERROR_SUCCESS
            error(Base.Libc.FormatMessage(code))
        end

        # Step 3: Convert encrypted credentials back to plain text
        passbuf = Array(UInt16, 1024)
        passlen = Ref{UInt32}(length(passbuf))
        usernamebuf = Array(UInt16, 1024)
        usernamelen = Ref{UInt32}(length(usernamebuf))
        # Need valid buffers for domain, even though we don't care
        dummybuf = Array(UInt16, 1024)
        succeeded = ccall((:CredUnPackAuthenticationBufferW, "Credui.dll"), Bool,
            (UInt32, Ptr{Void}, UInt32, Ptr{UInt16}, Ptr{UInt32}, Ptr{UInt16}, Ptr{UInt32}, Ptr{UInt16}, Ptr{UInt32}),
            0, outbuf_data[], outbuf_size[], usernamebuf, usernamelen, dummybuf, Ref{UInt32}(1024), passbuf, passlen)
        if !succeeded
            error(Base.Libc.FormatMessage())
        end

        # Step 4: Free the encrypted buffer
        # ccall(:SecureZeroMemory, Ptr{Void}, (Ptr{Void}, Csize_t), outbuf_data[], outbuf_size[]) - not an actual function
        ccall((:CoTaskMemFree, "Ole32.dll"), Void, (Ptr{Void},), outbuf_data[])

        # Done
        Nullable((String(transcode(UInt8, usernamebuf[1:usernamelen[]-1])),
            String(transcode(UInt8, passbuf[1:passlen[]-1]))))
    end

end