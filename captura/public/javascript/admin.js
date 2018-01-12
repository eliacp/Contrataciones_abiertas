//admin

$("#adminModal").on('show.bs.modal', function (event) {
    var button = $(event.relatedTarget);
    var modal = $(this);

    switch (button.data('action')){
        case 'new_user':
            modal.find('.modal-title').text('Registrar usuario');
            modal.find('#modal_content').html("");
            modal.find('#modal_content').load("/admin/new-user.html", function () {
                $(this).find('form').submit(function (e) {
                    $.post('/user', $(this).serialize()).done(function (data) {
                        alert(data.message);
                        if (data.status === 'Ok'){
                            modal.modal('hide');
                        }
                    });
                    e.preventDefault();
                })
            });
            break;

        case 'users':
            modal.find('.modal-title').text('Usuarios');
            modal.find('#modal_content').html("");
            modal.find('#modal_content').load('/admin/users.html',function () {

            });
    }
});