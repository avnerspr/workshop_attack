from eval_client import send_answer

if __name__ == "__main__":
    print(send_answer("Eyal", "test", "wrong"))
    print(send_answer("Eyal", "test", "right"))
    print(send_answer("Eyal", "nottest", "right"))
