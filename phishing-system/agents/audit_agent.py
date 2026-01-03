import logging

logging.basicConfig(filename="audit_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

def log_result(file_path, result, usage):
    log_msg = (
        f"File: {file_path}\n"
        f"Result: {result}\n"
        f"Tokens: Prompt={usage['prompt_tokens']}, Completion={usage['completion_tokens']}, Total={usage['total_tokens']}\n"
        "------------------------------"
    )
    logging.info(log_msg)
