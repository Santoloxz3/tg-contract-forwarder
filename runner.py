import asyncio
import main

# main.LOGIN_HTML contains CSS braces. Escape them before main.py calls str.format(error=...).
main.LOGIN_HTML = (
    main.LOGIN_HTML
    .replace("{", "{{")
    .replace("}", "}}")
    .replace("{{error}}", "{error}")
)

asyncio.run(main.main())
