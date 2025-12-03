import os

def create_dummy_csv(filename="test_dataset.csv"):
    if not os.path.exists(filename):
        print(f"[SETUP] Generating dummy file '{filename}' di {os.getcwd()}...")
        with open(filename, "w") as f:
            f.write("ID,Name,GPA,Subject\n")
            f.write("101,Faiz,3.5,Data Science\n")
            f.write("102,Gres,3.8,Informatika\n")
            f.write("103,Haikal,3.2,Sistem Informasi")
    return filename