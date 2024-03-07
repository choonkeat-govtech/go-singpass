# Singpass

Add Singpass Login support to your Go HTTP application

```go
http.HandleFunc("/mysingpass/start", singpass.RedirectToSingpass(cfg, singpass.NonceStateToCookie, errHandler))
http.HandleFunc("/mysingpass/callback", singpassCallbackHandler)
```

After some configuration, see `internal/example.go`
