# DeepSeek Harness code-change fixture

This source tree represents the frozen input used by the v0.1 end-to-end
developer preflight. The verified patch changes `src/app.py` from `base` to
`patched`; the exported delivery bundle must then verify offline and fail after
any artifact is changed.
