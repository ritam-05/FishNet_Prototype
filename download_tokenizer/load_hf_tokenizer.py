from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("google/electra-small-discriminator")
tokenizer.save_pretrained("./android_tokenizer")
