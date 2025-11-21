namespace ADAuthentication.PL.Models
{
    public class ApiResponse<T>
    {
        public bool Status { get; set; }

        public string Message { get; set; }

        public string Errors { get; set; }

        public T Data { get; set; }

        public Exception Exception { get; set; }


        public ApiResponse()
        {
            Status = true;
        }
    }
}
